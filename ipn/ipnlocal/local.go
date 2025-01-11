// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnlocal is the heart of the Tailscale node agent that controls
// all the other misc pieces of the Tailscale node.
package ipnlocal

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/netipx"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/control/controlclient"
	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/envknob/featureknob"
	"tailscale.com/health"
	"tailscale.com/health/healthmsg"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/policy"
	"tailscale.com/net/ipset"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/paths"
	"tailscale.com/portlist"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstime"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/deephash"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/goroutines"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
	"tailscale.com/util/osuser"
	"tailscale.com/util/rands"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/syspolicy"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/testenv"
	"tailscale.com/util/uniq"
	"tailscale.com/util/usermetric"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/capture"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgcfg/nmcfg"
)

var controlDebugFlags = getControlDebugFlags()

func getControlDebugFlags() []string {
	if e := envknob.String("TS_DEBUG_CONTROL_FLAGS"); e != "" {
		return strings.Split(e, ",")
	}
	return nil
}

// SSHServer is the interface of the conditionally linked ssh/tailssh.server.
type SSHServer interface {
	HandleSSHConn(net.Conn) error

	// NumActiveConns returns the number of connections passed to HandleSSHConn
	// that are still active.
	NumActiveConns() int

	// OnPolicyChange is called when the SSH access policy changes,
	// so that existing sessions can be re-evaluated for validity
	// and closed if they'd no longer be accepted.
	OnPolicyChange()

	// Shutdown is called when tailscaled is shutting down.
	Shutdown()
}

type newSSHServerFunc func(logger.Logf, *LocalBackend) (SSHServer, error)

var newSSHServer newSSHServerFunc // or nil

// RegisterNewSSHServer lets the conditionally linked ssh/tailssh package register itself.
func RegisterNewSSHServer(fn newSSHServerFunc) {
	newSSHServer = fn
}

// watchSession represents a WatchNotifications channel,
// an [ipnauth.Actor] that owns it (e.g., a connected GUI/CLI),
// and sessionID as required to close targeted buses.
type watchSession struct {
	ch        chan *ipn.Notify
	owner     ipnauth.Actor // or nil
	sessionID string
	cancel    context.CancelFunc // to shut down the session
}

// LocalBackend is the glue between the major pieces of the Tailscale
// network software: the cloud control plane (via controlclient), the
// network data plane (via wgengine), and the user-facing UIs and CLIs
// (collectively called "frontends", via LocalBackend's implementation
// of the Backend interface).
//
// LocalBackend implements the overall state machine for the Tailscale
// application. Frontends, controlclient and wgengine can feed events
// into LocalBackend to advance the state machine, and advancing the
// state machine generates events back out to zero or more components.
type LocalBackend struct {
	// Elements that are thread-safe or constant after construction.
	ctx                      context.Context    // canceled by [LocalBackend.Shutdown]
	ctxCancel                context.CancelFunc // cancels ctx
	logf                     logger.Logf        // general logging
	keyLogf                  logger.Logf        // for printing list of peers on change
	statsLogf                logger.Logf        // for printing peers stats on change
	sys                      *tsd.System
	health                   *health.Tracker // always non-nil
	metrics                  metrics
	e                        wgengine.Engine // non-nil; TODO(bradfitz): remove; use sys
	store                    ipn.StateStore  // non-nil; TODO(bradfitz): remove; use sys
	dialer                   *tsdial.Dialer  // non-nil; TODO(bradfitz): remove; use sys
	pushDeviceToken          syncs.AtomicValue[string]
	backendLogID             logid.PublicID
	unregisterNetMon         func()
	unregisterHealthWatch    func()
	unregisterSysPolicyWatch func()
	portpoll                 *portlist.Poller // may be nil
	portpollOnce             sync.Once        // guards starting readPoller
	varRoot                  string           // or empty if SetVarRoot never called
	logFlushFunc             func()           // or nil if SetLogFlusher wasn't called
	em                       *expiryManager   // non-nil
	sshAtomicBool            atomic.Bool
	// webClientAtomicBool controls whether the web client is running. This should
	// be true unless the disable-web-client node attribute has been set.
	webClientAtomicBool atomic.Bool
	// exposeRemoteWebClientAtomicBool controls whether the web client is exposed over
	// Tailscale on port 5252.
	exposeRemoteWebClientAtomicBool atomic.Bool
	shutdownCalled                  bool // if Shutdown has been called
	debugSink                       *capture.Sink

	// getTCPHandlerForFunnelFlow returns a handler for an incoming TCP flow for
	// the provided srcAddr and dstPort if one exists.
	//
	// srcAddr is the source address of the flow, not the address of the Funnel
	// node relaying the flow.
	// dstPort is the destination port of the flow.
	//
	// It returns nil if there is no known handler for this flow.
	//
	// This is specifically used to handle TCP flows for Funnel connections to tsnet
	// servers.
	//
	// It is set once during initialization, and can be nil if SetTCPHandlerForFunnelFlow
	// is never called.
	getTCPHandlerForFunnelFlow func(srcAddr netip.AddrPort, dstPort uint16) (handler func(net.Conn))

	filterAtomic                 atomic.Pointer[filter.Filter]
	containsViaIPFuncAtomic      syncs.AtomicValue[func(netip.Addr) bool]
	shouldInterceptTCPPortAtomic syncs.AtomicValue[func(uint16) bool]
	numClientStatusCalls         atomic.Uint32

	// goTracker accounts for all goroutines started by LocalBacked, primarily
	// for testing and graceful shutdown purposes.
	goTracker goroutines.Tracker

	// The mutex protects the following elements.
	mu             sync.Mutex
	conf           *conffile.Config // latest parsed config, or nil if not in declarative mode
	pm             *profileManager  // mu guards access
	filterHash     deephash.Sum
	httpTestClient *http.Client // for controlclient. nil by default, used by tests.
	ccGen          clientGen    // function for producing controlclient; lazily populated
	sshServer      SSHServer    // or nil, initialized lazily.
	// notifyCancel cancels notifications to the current SetNotifyCallback.
	notifyCancel   context.CancelFunc
	cc             controlclient.Client
	ccAuto         *controlclient.Auto // if cc is of type *controlclient.Auto
	machinePrivKey key.MachinePrivate
	tka            *int
	state          ipn.State
	capFileSharing bool // whether netMap contains the file sharing capability
	capTailnetLock bool // whether netMap contains the tailnet lock capability
	// hostinfo is mutated in-place while mu is held.
	hostinfo *tailcfg.Hostinfo
	// netMap is the most recently set full netmap from the controlclient.
	// It can't be mutated in place once set. Because it can't be mutated in place,
	// delta updates from the control server don't apply to it. Instead, use
	// the peers map to get up-to-date information on the state of peers.
	// In general, avoid using the netMap.Peers slice. We'd like it to go away
	// as of 2023-09-17.
	netMap *netmap.NetworkMap
	// peers is the set of current peers and their current values after applying
	// delta node mutations as they come in (with mu held). The map values can
	// be given out to callers, but the map itself must not escape the LocalBackend.
	peers          map[tailcfg.NodeID]tailcfg.NodeView
	nodeByAddr     map[netip.Addr]tailcfg.NodeID // by Node.Addresses only (not subnet routes)
	nmExpiryTimer  tstime.TimerController        // for updating netMap on node expiry; can be nil
	activeLogin    string                        // last logged LoginName from netMap
	engineStatus   ipn.EngineStatus
	endpoints      []tailcfg.Endpoint
	blocked        bool
	keyExpired     bool
	authURL        string        // non-empty if not Running
	authURLTime    time.Time     // when the authURL was received from the control server
	authActor      ipnauth.Actor // an actor who called [LocalBackend.StartLoginInteractive] last, or nil
	egg            bool
	prevIfState    *netmon.State
	loginFlags     controlclient.LoginFlags
	fileWaiters    set.HandleSet[context.CancelFunc] // of wake-up funcs
	notifyWatchers map[string]*watchSession          // by session ID
	lastStatusTime time.Time                         // status.AsOf value of the last processed status update
	// directFileRoot, if non-empty, means to write received files
	// directly to this directory, without staging them in an
	// intermediate buffered directory for "pick-up" later. If
	// empty, the files are received in a daemon-owned location
	// and the localapi is used to enumerate, download, and delete
	// them. This is used on macOS where the GUI lifetime is the
	// same as the Network Extension lifetime and we can thus avoid
	// double-copying files by writing them to the right location
	// immediately.
	// It's also used on several NAS platforms (Synology, TrueNAS, etc)
	// but in that case DoFinalRename is also set true, which moves the
	// *.partial file to its final name on completion.
	directFileRoot    string
	componentLogUntil map[string]componentLogState
	// c2nUpdateStatus is the status of c2n-triggered client update.
	c2nUpdateStatus     updateStatus
	currentUser         ipnauth.Actor
	selfUpdateProgress  []ipnstate.UpdateProgress
	lastSelfUpdateState ipnstate.SelfUpdateStatus
	// capForcedNetfilter is the netfilter that control instructs Linux clients
	// to use, unless overridden locally.
	capForcedNetfilter string
	// offlineAutoUpdateCancel stops offline auto-updates when called. It
	// should be used via stopOfflineAutoUpdate and
	// maybeStartOfflineAutoUpdate. It is nil when offline auto-updates are
	// note running.
	//
	//lint:ignore U1000 only used in Linux and Windows builds in autoupdate.go
	offlineAutoUpdateCancel func()

	// statusLock must be held before calling statusChanged.Wait() or
	// statusChanged.Broadcast().
	statusLock    sync.Mutex
	statusChanged *sync.Cond

	// dialPlan is any dial plan that we've received from the control
	// server during a previous connection; it is cleared on logout.
	dialPlan atomic.Pointer[tailcfg.ControlDialPlan]

	// tkaSyncLock is used to make tkaSyncIfNeeded an exclusive
	// section. This is needed to stop two map-responses in quick succession
	// from racing each other through TKA sync logic / RPCs.
	//
	// tkaSyncLock MUST be taken before mu (or inversely, mu must not be held
	// at the moment that tkaSyncLock is taken).
	tkaSyncLock sync.Mutex
	clock       tstime.Clock

	// Last ClientVersion received in MapResponse, guarded by mu.
	lastClientVersion *tailcfg.ClientVersion

	// lastNotifiedDriveSharesMu guards lastNotifiedDriveShares
	lastNotifiedDriveSharesMu sync.Mutex
	// outgoingFiles keeps track of Taildrop outgoing files keyed to their OutgoingFile.ID
	outgoingFiles map[string]*ipn.OutgoingFile

	// lastSuggestedExitNode stores the last suggested exit node suggestion to
	// avoid unnecessary churn between multiple equally-good options.
	lastSuggestedExitNode tailcfg.StableNodeID

	// allowedSuggestedExitNodes is a set of exit nodes permitted by the most recent
	// [syspolicy.AllowedSuggestedExitNodes] value. The allowedSuggestedExitNodesMu
	// mutex guards access to this set.
	allowedSuggestedExitNodesMu sync.Mutex
	allowedSuggestedExitNodes   set.Set[tailcfg.StableNodeID]

	// refreshAutoExitNode indicates if the exit node should be recomputed when the next netcheck report is available.
	refreshAutoExitNode bool // guarded by mu

	// captiveCtx and captiveCancel are used to control captive portal
	// detection. They are protected by 'mu' and can be changed during the
	// lifetime of a LocalBackend.
	//
	// captiveCtx will always be non-nil, though it might be a canceled
	// context. captiveCancel is non-nil if checkCaptivePortalLoop is
	// running, and is set to nil after being canceled.
	captiveCtx    context.Context
	captiveCancel context.CancelFunc
	// needsCaptiveDetection is a channel that is used to signal either
	// that captive portal detection is required (sending true) or that the
	// backend is healthy and captive portal detection is not required
	// (sending false).
	needsCaptiveDetection chan bool
}

// HealthTracker returns the health tracker for the backend.
func (b *LocalBackend) HealthTracker() *health.Tracker {
	return b.health
}

// UserMetricsRegistry returns the usermetrics registry for the backend
func (b *LocalBackend) UserMetricsRegistry() *usermetric.Registry {
	return b.sys.UserMetricsRegistry()
}

// NetMon returns the network monitor for the backend.
func (b *LocalBackend) NetMon() *netmon.Monitor {
	return b.sys.NetMon.Get()
}

type updateStatus struct {
	started bool
}

type metrics struct {
	// advertisedRoutes is a metric that reports the number of network routes that are advertised by the local node.
	// This informs the user of how many routes are being advertised by the local node, excluding exit routes.
	advertisedRoutes *usermetric.Gauge

	// approvedRoutes is a metric that reports the number of network routes served by the local node and approved
	// by the control server.
	approvedRoutes *usermetric.Gauge
}

// clientGen is a func that creates a control plane client.
// It's the type used by LocalBackend.SetControlClientGetterForTesting.
type clientGen func(controlclient.Options) (controlclient.Client, error)

// NewLocalBackend returns a new LocalBackend that is ready to run,
// but is not actually running.
//
// If dialer is nil, a new one is made.
func NewLocalBackend(logf logger.Logf, sys *tsd.System, loginFlags controlclient.LoginFlags) (_ *LocalBackend, err error) {
	e := sys.Engine.Get()
	store := sys.StateStore.Get()
	dialer := sys.Dialer.Get()
	if dialer == nil {
		return nil, errors.New("dialer to NewLocalBackend must be set")
	}
	if dialer.NetMon() == nil {
		return nil, errors.New("dialer to NewLocalBackend must have a NetMon")
	}
	mConn := sys.MagicSock.Get()

	goos := envknob.GOOS()
	if loginFlags&controlclient.LocalBackendStartKeyOSNeutral != 0 {
		goos = ""
	}
	pm, err := newProfileManagerWithGOOS(store, logf, sys.HealthTracker(), goos)
	if err != nil {
		return nil, err
	}
	if sds, ok := store.(ipn.StateStoreDialerSetter); ok {
		sds.SetDialer(dialer.SystemDial)
	}

	envknob.LogCurrent(logf)

	ctx, cancel := context.WithCancel(context.Background())
	clock := tstime.StdClock{}

	// Until we transition to a Running state, use a canceled context for
	// our captive portal detection.
	captiveCtx, captiveCancel := context.WithCancel(ctx)
	captiveCancel()

	m := metrics{
		advertisedRoutes: sys.UserMetricsRegistry().NewGauge(
			"tailscaled_advertised_routes", "Number of advertised network routes (e.g. by a subnet router)"),
		approvedRoutes: sys.UserMetricsRegistry().NewGauge(
			"tailscaled_approved_routes", "Number of approved network routes (e.g. by a subnet router)"),
	}

	b := &LocalBackend{
		ctx:                   ctx,
		ctxCancel:             cancel,
		logf:                  logf,
		keyLogf:               logger.LogOnChange(logf, 5*time.Minute, clock.Now),
		statsLogf:             logger.LogOnChange(logf, 5*time.Minute, clock.Now),
		sys:                   sys,
		health:                sys.HealthTracker(),
		metrics:               m,
		e:                     e,
		dialer:                dialer,
		store:                 store,
		pm:                    pm,
		state:                 ipn.NoState,
		portpoll:              new(portlist.Poller),
		em:                    newExpiryManager(logf),
		loginFlags:            loginFlags,
		clock:                 clock,
		selfUpdateProgress:    make([]ipnstate.UpdateProgress, 0),
		lastSelfUpdateState:   ipnstate.UpdateFinished,
		captiveCtx:            captiveCtx,
		captiveCancel:         nil, // so that we start checkCaptivePortalLoop when Running
		needsCaptiveDetection: make(chan bool),
	}
	mConn.SetNetInfoCallback(b.setNetInfo)

	if sys.InitialConfig != nil {
		if err := b.initPrefsFromConfig(sys.InitialConfig); err != nil {
			return nil, err
		}
	}

	if b.unregisterSysPolicyWatch, err = b.registerSysPolicyWatch(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			b.unregisterSysPolicyWatch()
		}
	}()

	netMon := sys.NetMon.Get()

	// Default filter blocks everything and logs nothing, until Start() is called.
	noneFilter := filter.NewAllowNone(logf, &netipx.IPSet{})
	b.setFilter(noneFilter)
	b.e.SetJailedFilter(noneFilter)

	b.setTCPPortsIntercepted(nil)

	b.statusChanged = sync.NewCond(&b.statusLock)
	b.e.SetStatusCallback(b.setWgengineStatus)

	b.prevIfState = netMon.InterfaceState()
	// Call our linkChange code once with the current state, and
	// then also whenever it changes:
	b.linkChange(&netmon.ChangeDelta{New: netMon.InterfaceState()})
	b.unregisterNetMon = netMon.RegisterChangeCallback(b.linkChange)

	b.unregisterHealthWatch = b.health.RegisterWatcher(b.onHealthChange)

	for _, component := range ipn.DebuggableComponents {
		key := componentStateKey(component)
		if ut, err := ipn.ReadStoreInt(pm.Store(), key); err == nil {
			if until := time.Unix(ut, 0); until.After(b.clock.Now()) {
				// conditional to avoid log spam at start when off
				b.SetComponentDebugLogging(component, until)
			}
		}
	}

	return b, nil
}

type componentLogState struct {
	until time.Time
	timer tstime.TimerController // if non-nil, the AfterFunc to disable it
}

func componentStateKey(component string) ipn.StateKey {
	return ipn.StateKey("_debug_" + component + "_until")
}

// SetComponentDebugLogging sets component's debug logging enabled until the until time.
// If until is in the past, the component's debug logging is disabled.
//
// The following components are recognized:
//
//   - magicsock
//   - sockstats
func (b *LocalBackend) SetComponentDebugLogging(component string, until time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var setEnabled func(bool)
	switch component {
	case "magicsock":
		setEnabled = b.MagicConn().SetDebugLoggingEnabled
	case "syspolicy":
		setEnabled = syspolicy.SetDebugLoggingEnabled
	}
	if setEnabled == nil || !slices.Contains(ipn.DebuggableComponents, component) {
		return fmt.Errorf("unknown component %q", component)
	}
	timeUnixOrZero := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Unix()
	}
	ipn.PutStoreInt(b.store, componentStateKey(component), timeUnixOrZero(until))
	now := b.clock.Now()
	on := now.Before(until)
	setEnabled(on)
	var onFor time.Duration
	if on {
		onFor = until.Sub(now)
		b.logf("debugging logging for component %q enabled for %v (until %v)", component, onFor.Round(time.Second), until.UTC().Format(time.RFC3339))
	} else {
		b.logf("debugging logging for component %q disabled", component)
	}
	if oldSt, ok := b.componentLogUntil[component]; ok && oldSt.timer != nil {
		oldSt.timer.Stop()
	}
	newSt := componentLogState{until: until}
	if on {
		newSt.timer = b.clock.AfterFunc(onFor, func() {
			// Turn off logging after the timer fires, as long as the state is
			// unchanged when the timer actually fires.
			b.mu.Lock()
			defer b.mu.Unlock()
			if ls := b.componentLogUntil[component]; ls.until.Equal(until) {
				setEnabled(false)
				b.logf("debugging logging for component %q disabled (by timer)", component)
			}
		})
	}
	mak.Set(&b.componentLogUntil, component, newSt)
	return nil
}

// GetComponentDebugLogging gets the time that component's debug logging is
// enabled until, or the zero time if component's time is not currently
// enabled.
func (b *LocalBackend) GetComponentDebugLogging(component string) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.clock.Now()
	ls := b.componentLogUntil[component]
	if ls.until.IsZero() || ls.until.Before(now) {
		return time.Time{}
	}
	return ls.until
}

// Dialer returns the backend's dialer.
// It is always non-nil.
func (b *LocalBackend) Dialer() *tsdial.Dialer {
	return b.dialer
}

// SetDirectFileRoot sets the directory to download files to directly,
// without buffering them through an intermediate daemon-owned
// tailcfg.UserID-specific directory.
//
// This must be called before the LocalBackend starts being used.
func (b *LocalBackend) SetDirectFileRoot(dir string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.directFileRoot = dir
}

// ReloadConfig reloads the backend's config from disk.
//
// It returns (false, nil) if not running in declarative mode, (true, nil) on
// success, or (false, error) on failure.
func (b *LocalBackend) ReloadConfig() (ok bool, err error) {
	unlock := b.lockAndGetUnlock()
	defer unlock()
	if b.conf == nil {
		return false, nil
	}
	conf, err := conffile.Load(b.conf.Path)
	if err != nil {
		return false, err
	}
	if err := b.setConfigLockedOnEntry(conf, unlock); err != nil {
		return false, fmt.Errorf("error setting config: %w", err)
	}

	return true, nil
}

// initPrefsFromConfig initializes the backend's prefs from the provided config.
// This should only be called once, at startup. For updates at runtime, use
// [LocalBackend.setConfigLocked].
func (b *LocalBackend) initPrefsFromConfig(conf *conffile.Config) error {
	// TODO(maisem,bradfitz): combine this with setConfigLocked. This is called
	// before anything is running, so there's no need to lock and we don't
	// update any subsystems. At runtime, we both need to lock and update
	// subsystems with the new prefs.
	p := b.pm.CurrentPrefs().AsStruct()
	mp, err := conf.Parsed.ToPrefs()
	if err != nil {
		return fmt.Errorf("error parsing config to prefs: %w", err)
	}
	p.ApplyEdits(&mp)
	if err := b.pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
		return err
	}
	b.setStaticEndpointsFromConfigLocked(conf)
	b.conf = conf
	return nil
}

func (b *LocalBackend) setStaticEndpointsFromConfigLocked(conf *conffile.Config) {
	if conf.Parsed.StaticEndpoints == nil && (b.conf == nil || b.conf.Parsed.StaticEndpoints == nil) {
		return
	}

	// Ensure that magicsock conn has the up to date static wireguard
	// endpoints. Setting the endpoints here triggers an asynchronous update
	// of the node's advertised endpoints.
	if b.conf == nil && len(conf.Parsed.StaticEndpoints) != 0 || !reflect.DeepEqual(conf.Parsed.StaticEndpoints, b.conf.Parsed.StaticEndpoints) {
		ms, ok := b.sys.MagicSock.GetOK()
		if !ok {
			b.logf("[unexpected] ReloadConfig: MagicSock not set")
		} else {
			ms.SetStaticEndpoints(views.SliceOf(conf.Parsed.StaticEndpoints))
		}
	}
}

// setConfigLockedOnEntry uses the provided config to update the backend's prefs
// and other state.
func (b *LocalBackend) setConfigLockedOnEntry(conf *conffile.Config, unlock unlockOnce) error {
	defer unlock()
	p := b.pm.CurrentPrefs().AsStruct()
	mp, err := conf.Parsed.ToPrefs()
	if err != nil {
		return fmt.Errorf("error parsing config to prefs: %w", err)
	}
	p.ApplyEdits(&mp)
	b.setStaticEndpointsFromConfigLocked(conf)
	b.setPrefsLockedOnEntry(p, unlock)

	b.conf = conf
	return nil
}

var assumeNetworkUpdateForTest = envknob.RegisterBool("TS_ASSUME_NETWORK_UP_FOR_TEST")

// pauseOrResumeControlClientLocked pauses b.cc if there is no network available
// or if the LocalBackend is in Stopped state with a valid NetMap. In all other
// cases, it unpauses it. It is a no-op if b.cc is nil.
//
// b.mu must be held.
func (b *LocalBackend) pauseOrResumeControlClientLocked() {
	if b.cc == nil {
		return
	}
	networkUp := b.prevIfState.AnyInterfaceUp()
	b.cc.SetPaused((b.state == ipn.Stopped && b.netMap != nil) || (!networkUp && !testenv.InTest() && !assumeNetworkUpdateForTest()))
}

// DisconnectControl shuts down control client. This can be run before node shutdown to force control to consider this ndoe
// inactive. This can be used to ensure that nodes that are HA subnet router or app connector replicas are shutting
// down, clients switch over to other replicas whilst the existing connections are kept alive for some period of time.
func (b *LocalBackend) DisconnectControl() {
	b.mu.Lock()
	defer b.mu.Unlock()
	cc := b.resetControlClientLocked()
	if cc == nil {
		return
	}
	cc.Shutdown()
}

// captivePortalDetectionInterval is the duration to wait in an unhealthy state with connectivity broken
// before running captive portal detection.
const captivePortalDetectionInterval = 2 * time.Second

// linkChange is our network monitor callback, called whenever the network changes.
func (b *LocalBackend) linkChange(delta *netmon.ChangeDelta) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ifst := delta.New
	hadPAC := b.prevIfState.HasPAC()
	b.prevIfState = ifst
	b.pauseOrResumeControlClientLocked()
	if delta.Major && shouldAutoExitNode() {
		b.refreshAutoExitNode = true
	}

	var needReconfig bool
	// If the network changed and we're using an exit node and allowing LAN access, we may need to reconfigure.
	if delta.Major && b.pm.CurrentPrefs().ExitNodeID() != "" && b.pm.CurrentPrefs().ExitNodeAllowLANAccess() {
		b.logf("linkChange: in state %v; updating LAN routes", b.state)
		needReconfig = true
	}
	// If the PAC-ness of the network changed, reconfig wireguard+route to add/remove subnets.
	if hadPAC != ifst.HasPAC() {
		b.logf("linkChange: in state %v; PAC changed from %v->%v", b.state, hadPAC, ifst.HasPAC())
		needReconfig = true
	}
	if needReconfig {
		switch b.state {
		case ipn.NoState, ipn.Stopped:
			// Do nothing.
		default:
			// TODO(raggi,tailscale/corp#22574): authReconfig should be refactored such that we can call the
			// necessary operations here and avoid the need for asynchronous behavior that is racy and hard
			// to test here, and do less extra work in these conditions.
			b.goTracker.Go(b.authReconfig)
		}
	}

	// If the local network configuration has changed, our filter may
	// need updating to tweak default routes.
	b.updateFilterLocked(b.netMap, b.pm.CurrentPrefs())
	updateExitNodeUsageWarning(b.pm.CurrentPrefs(), delta.New, b.health)
}

func (b *LocalBackend) onHealthChange(w *health.Warnable, us *health.UnhealthyState) {
	if us == nil {
		b.logf("health(warnable=%s): ok", w.Code)
	} else {
		b.logf("health(warnable=%s): error: %s", w.Code, us.Text)
	}

	// Whenever health changes, send the current health state to the frontend.
	state := b.health.CurrentState()
	b.send(ipn.Notify{
		Health: state,
	})

	isConnectivityImpacted := false
	for _, w := range state.Warnings {
		// Ignore the captive portal warnable itself.
		if w.ImpactsConnectivity && w.WarnableCode != captivePortalWarnable.Code {
			isConnectivityImpacted = true
			break
		}
	}

	// captiveCtx can be changed, and is protected with 'mu'; grab that
	// before we start our select, below.
	//
	// It is guaranteed to be non-nil.
	b.mu.Lock()
	ctx := b.captiveCtx
	b.mu.Unlock()

	// If the context is canceled, we don't need to do anything.
	if ctx.Err() != nil {
		return
	}

	if isConnectivityImpacted {
		b.logf("health: connectivity impacted; triggering captive portal detection")

		// Ensure that we select on captiveCtx so that we can time out
		// triggering captive portal detection if the backend is shutdown.
		select {
		case b.needsCaptiveDetection <- true:
		case <-ctx.Done():
		}
	} else {
		// If connectivity is not impacted, we know for sure we're not behind a captive portal,
		// so drop any warning, and signal that we don't need captive portal detection.
		b.health.SetHealthy(captivePortalWarnable)
		select {
		case b.needsCaptiveDetection <- false:
		case <-ctx.Done():
		}
	}
}

// Shutdown halts the backend and all its sub-components. The backend
// can no longer be used after Shutdown returns.
func (b *LocalBackend) Shutdown() {
	b.mu.Lock()
	if b.shutdownCalled {
		b.mu.Unlock()
		return
	}
	b.shutdownCalled = true

	if b.captiveCancel != nil {
		b.logf("canceling captive portal context")
		b.captiveCancel()
	}

	if b.loginFlags&controlclient.LoginEphemeral != 0 {
		b.mu.Unlock()
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		defer cancel()
		t0 := time.Now()
		err := b.Logout(ctx) // best effort
		td := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			b.logf("failed to log out ephemeral node on shutdown after %v: %v", td, err)
		} else {
			b.logf("logged out ephemeral node on shutdown")
		}
		b.mu.Lock()
	}
	cc := b.cc
	if b.sshServer != nil {
		b.sshServer.Shutdown()
		b.sshServer = nil
	}
	if b.debugSink != nil {
		b.debugSink.Close()
		b.debugSink = nil
	}
	if b.notifyCancel != nil {
		b.notifyCancel()
	}
	b.mu.Unlock()

	b.unregisterNetMon()
	b.unregisterHealthWatch()
	b.unregisterSysPolicyWatch()
	if cc != nil {
		cc.Shutdown()
	}
	b.ctxCancel()
	b.e.Close()
	<-b.e.Done()
	b.awaitNoGoroutinesInTest()
}

func (b *LocalBackend) awaitNoGoroutinesInTest() {
	if !testenv.InTest() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	ch := make(chan bool, 1)
	defer b.goTracker.AddDoneCallback(func() { ch <- true })()

	for {
		n := b.goTracker.RunningGoroutines()
		if n == 0 {
			return
		}
		select {
		case <-ctx.Done():
			// TODO(bradfitz): pass down some TB-like failer interface from
			// tests, without depending on testing from here?
			// But this is fine in tests too:
			panic(fmt.Sprintf("timeout waiting for %d goroutines to stop", n))
		case <-ch:
		}
	}
}

func stripKeysFromPrefs(p ipn.PrefsView) ipn.PrefsView {
	if !p.Valid() || !p.Persist().Valid() {
		return p
	}

	p2 := p.AsStruct()
	p2.Persist.LegacyFrontendPrivateMachineKey = key.MachinePrivate{}
	p2.Persist.PrivateNodeKey = key.NodePrivate{}
	p2.Persist.OldPrivateNodeKey = key.NodePrivate{}
	p2.Persist.NetworkLockKey = key.NLPrivate{}
	return p2.View()
}

// Prefs returns a copy of b's current prefs, with any private keys removed.
func (b *LocalBackend) Prefs() ipn.PrefsView {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sanitizedPrefsLocked()
}

func (b *LocalBackend) sanitizedPrefsLocked() ipn.PrefsView {
	return stripKeysFromPrefs(b.pm.CurrentPrefs())
}

// Status returns the latest status of the backend and its
// sub-components.
func (b *LocalBackend) Status() *ipnstate.Status {
	sb := &ipnstate.StatusBuilder{WantPeers: true}
	b.UpdateStatus(sb)
	return sb.Status()
}

// StatusWithoutPeers is like Status but omits any details
// of peers.
func (b *LocalBackend) StatusWithoutPeers() *ipnstate.Status {
	sb := &ipnstate.StatusBuilder{WantPeers: false}
	b.UpdateStatus(sb)
	return sb.Status()
}

// UpdateStatus implements ipnstate.StatusUpdater.
func (b *LocalBackend) UpdateStatus(sb *ipnstate.StatusBuilder) {
	b.e.UpdateStatus(sb) // does wireguard + magicsock status

	b.mu.Lock()
	defer b.mu.Unlock()

	sb.MutateStatus(func(s *ipnstate.Status) {
		s.Version = version.Long()
		s.TUN = !b.sys.IsNetstack()
		s.BackendState = b.state.String()
		s.AuthURL = b.authURL
		if prefs := b.pm.CurrentPrefs(); prefs.Valid() && prefs.AutoUpdate().Check {
			s.ClientVersion = b.lastClientVersion
		}
		s.Health = b.health.Strings()
		s.HaveNodeKey = b.hasNodeKeyLocked()

		// TODO(bradfitz): move this health check into a health.Warnable
		// and remove from here.
		if m := b.sshOnButUnusableHealthCheckMessageLocked(); m != "" {
			s.Health = append(s.Health, m)
		}
		if b.netMap != nil {
			s.CertDomains = append([]string(nil), b.netMap.DNS.CertDomains...)
			s.MagicDNSSuffix = b.netMap.MagicDNSSuffix()
			if s.CurrentTailnet == nil {
				s.CurrentTailnet = &ipnstate.TailnetStatus{}
			}
			s.CurrentTailnet.MagicDNSSuffix = b.netMap.MagicDNSSuffix()
			s.CurrentTailnet.MagicDNSEnabled = b.netMap.DNS.Proxied
			s.CurrentTailnet.Name = b.netMap.Domain
			if prefs := b.pm.CurrentPrefs(); prefs.Valid() {
				if !prefs.RouteAll() && b.netMap.AnyPeersAdvertiseRoutes() {
					s.Health = append(s.Health, healthmsg.WarnAcceptRoutesOff)
				}
				if !prefs.ExitNodeID().IsZero() {
					if exitPeer, ok := b.netMap.PeerWithStableID(prefs.ExitNodeID()); ok {
						online := false
						if v := exitPeer.Online(); v != nil {
							online = *v
						}
						s.ExitNodeStatus = &ipnstate.ExitNodeStatus{
							ID:           prefs.ExitNodeID(),
							Online:       online,
							TailscaleIPs: exitPeer.Addresses().AsSlice(),
						}
					}
				}
			}
		}
	})

	var tailscaleIPs []netip.Addr
	if b.netMap != nil {
		addrs := b.netMap.GetAddresses()
		for i := range addrs.Len() {
			if addr := addrs.At(i); addr.IsSingleIP() {
				sb.AddTailscaleIP(addr.Addr())
				tailscaleIPs = append(tailscaleIPs, addr.Addr())
			}
		}
	}

	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
		ss.OS = version.OS()
		ss.Online = b.health.GetInPollNetMap()
		if b.netMap != nil {
			ss.InNetworkMap = true
			if hi := b.netMap.SelfNode.Hostinfo(); hi.Valid() {
				ss.HostName = hi.Hostname()
			}
			ss.DNSName = b.netMap.Name
			ss.UserID = b.netMap.User()
			if sn := b.netMap.SelfNode; sn.Valid() {
				peerStatusFromNode(ss, sn)
				if cm := sn.CapMap(); cm.Len() > 0 {
					ss.Capabilities = make([]tailcfg.NodeCapability, 1, cm.Len()+1)
					ss.Capabilities[0] = "HTTPS://TAILSCALE.COM/s/DEPRECATED-NODE-CAPS#see-https://github.com/tailscale/tailscale/issues/11508"
					ss.CapMap = make(tailcfg.NodeCapMap, sn.CapMap().Len())
					for k, v := range cm.All() {
						ss.CapMap[k] = v.AsSlice()
						ss.Capabilities = append(ss.Capabilities, k)
					}
					slices.Sort(ss.Capabilities[1:])
				}
			}
			for _, addr := range tailscaleIPs {
				ss.TailscaleIPs = append(ss.TailscaleIPs, addr)
			}

		} else {
			ss.HostName, _ = os.Hostname()
		}
	})
	// TODO: hostinfo, and its networkinfo
	// TODO: EngineStatus copy (and deprecate it?)

	if sb.WantPeers {
		b.populatePeerStatusLocked(sb)
	}
}

func (b *LocalBackend) populatePeerStatusLocked(sb *ipnstate.StatusBuilder) {
	if b.netMap == nil {
		return
	}
	for id, up := range b.netMap.UserProfiles {
		sb.AddUser(id, up)
	}
	exitNodeID := b.pm.CurrentPrefs().ExitNodeID()
	for _, p := range b.peers {
		var lastSeen time.Time
		if p.LastSeen() != nil {
			lastSeen = *p.LastSeen()
		}
		tailscaleIPs := make([]netip.Addr, 0, p.Addresses().Len())
		for i := range p.Addresses().Len() {
			addr := p.Addresses().At(i)
			if addr.IsSingleIP() && tsaddr.IsTailscaleIP(addr.Addr()) {
				tailscaleIPs = append(tailscaleIPs, addr.Addr())
			}
		}
		online := p.Online()
		ps := &ipnstate.PeerStatus{
			InNetworkMap:    true,
			UserID:          p.User(),
			AltSharerUserID: p.Sharer(),
			TailscaleIPs:    tailscaleIPs,
			HostName:        p.Hostinfo().Hostname(),
			DNSName:         p.Name(),
			OS:              p.Hostinfo().OS(),
			LastSeen:        lastSeen,
			Online:          online != nil && *online,
			ShareeNode:      p.Hostinfo().ShareeNode(),
			ExitNode:        p.StableID() != "" && p.StableID() == exitNodeID,
			SSH_HostKeys:    p.Hostinfo().SSH_HostKeys().AsSlice(),
			Location:        p.Hostinfo().Location(),
			Capabilities:    p.Capabilities().AsSlice(),
		}
		if cm := p.CapMap(); cm.Len() > 0 {
			ps.CapMap = make(tailcfg.NodeCapMap, cm.Len())
			for k, v := range cm.All() {
				ps.CapMap[k] = v.AsSlice()
			}
		}
		peerStatusFromNode(ps, p)

		p4, p6 := peerAPIPorts(p)
		if u := peerAPIURL(nodeIP(p, netip.Addr.Is4), p4); u != "" {
			ps.PeerAPIURL = append(ps.PeerAPIURL, u)
		}
		if u := peerAPIURL(nodeIP(p, netip.Addr.Is6), p6); u != "" {
			ps.PeerAPIURL = append(ps.PeerAPIURL, u)
		}
		sb.AddPeer(p.Key(), ps)
	}
}

// peerStatusFromNode copies fields that exist in the Node struct for
// current node and peers into the provided PeerStatus.
func peerStatusFromNode(ps *ipnstate.PeerStatus, n tailcfg.NodeView) {
	ps.PublicKey = n.Key()
	ps.ID = n.StableID()
	ps.Created = n.Created()
	ps.ExitNodeOption = tsaddr.ContainsExitRoutes(n.AllowedIPs())
	if n.Tags().Len() != 0 {
		v := n.Tags()
		ps.Tags = &v
	}
	if n.PrimaryRoutes().Len() != 0 {
		v := n.PrimaryRoutes()
		ps.PrimaryRoutes = &v
	}
	if n.AllowedIPs().Len() != 0 {
		v := n.AllowedIPs()
		ps.AllowedIPs = &v
	}

	if n.Expired() {
		ps.Expired = true
	}
	if t := n.KeyExpiry(); !t.IsZero() {
		t = t.Round(time.Second)
		ps.KeyExpiry = &t
	}
}

// WhoIsNodeKey returns the peer info of given public key, if it exists.
func (b *LocalBackend) WhoIsNodeKey(k key.NodePublic) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// TODO(bradfitz): add nodeByKey like nodeByAddr instead of walking peers.
	if b.netMap == nil {
		return n, u, false
	}
	if self := b.netMap.SelfNode; self.Valid() && self.Key() == k {
		return self, b.netMap.UserProfiles[self.User()], true
	}
	for _, n := range b.peers {
		if n.Key() == k {
			u, ok = b.netMap.UserProfiles[n.User()]
			return n, u, ok
		}
	}
	return n, u, false
}

var debugWhoIs = envknob.RegisterBool("TS_DEBUG_WHOIS")

// WhoIs reports the node and user who owns the node with the given IP:port.
// If the IP address is a Tailscale IP, the provided port may be 0.
//
// The 'proto' is used when looking up the IP:port in our proxy mapper; it
// tracks which local IP:ports correspond to connections proxied by tailscaled,
// and since tailscaled proxies both TCP and UDP, the 'proto' is needed to look
// up the correct IP:port based on the connection's protocol. If not provided,
// the lookup will be done for TCP and then UDP, in that order.
//
// If ok == true, n and u are valid.
func (b *LocalBackend) WhoIs(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	var zero tailcfg.NodeView
	b.mu.Lock()
	defer b.mu.Unlock()

	failf := func(format string, args ...any) (tailcfg.NodeView, tailcfg.UserProfile, bool) {
		if debugWhoIs() {
			args = append([]any{proto, ipp}, args...)
			b.logf("whois(%q, %v) :"+format, args...)
		}
		return zero, u, false
	}

	nid, ok := b.nodeByAddr[ipp.Addr()]
	if !ok {
		return failf("no node for proxymapped IP %v", ipp.Addr())
	}
	if b.netMap == nil {
		return failf("no netmap")
	}
	n, ok = b.peers[nid]
	if !ok {
		// Check if this the self-node, which would not appear in peers.
		if !b.netMap.SelfNode.Valid() || nid != b.netMap.SelfNode.ID() {
			return zero, u, false
		}
		n = b.netMap.SelfNode
	}
	u, ok = b.netMap.UserProfiles[n.User()]
	if !ok {
		return failf("no userprofile for node %v", n.Key())
	}
	return n, u, true
}

// PeerCaps returns the capabilities that remote src IP has to
// ths current node.
func (b *LocalBackend) PeerCaps(src netip.Addr) tailcfg.PeerCapMap {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peerCapsLocked(src)
}

func (b *LocalBackend) peerCapsLocked(src netip.Addr) tailcfg.PeerCapMap {
	if b.netMap == nil {
		return nil
	}
	filt := b.filterAtomic.Load()
	if filt == nil {
		return nil
	}
	addrs := b.netMap.GetAddresses()
	for i := range addrs.Len() {
		a := addrs.At(i)
		if !a.IsSingleIP() {
			continue
		}
		dst := a.Addr()
		if dst.BitLen() == src.BitLen() { // match on family
			return filt.CapsWithValues(src, dst)
		}
	}
	return nil
}

// SetControlClientStatus is the callback invoked by the control client whenever it posts a new status.
// Among other things, this is where we update the netmap, packet filters, DNS and DERP maps.
func (b *LocalBackend) SetControlClientStatus(c controlclient.Client, st controlclient.Status) {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	if b.cc != c {
		b.logf("Ignoring SetControlClientStatus from old client")
		return
	}
	if st.Err != nil {
		// The following do not depend on any data for which we need b locked.
		unlock.UnlockEarly()
		if errors.Is(st.Err, io.EOF) {
			b.logf("[v1] Received error: EOF")
			return
		}
		b.logf("Received error: %v", st.Err)
		var uerr controlclient.UserVisibleError
		if errors.As(st.Err, &uerr) {
			s := uerr.UserVisibleError()
			b.send(ipn.Notify{ErrMessage: &s})
		}
		return
	}

	// Track the number of calls
	currCall := b.numClientStatusCalls.Add(1)

	// Handle node expiry in the netmap
	if st.NetMap != nil {
		now := b.clock.Now()
		b.em.flagExpiredPeers(st.NetMap, now)

		// Always stop the existing netmap timer if we have a netmap;
		// it's possible that we have no nodes expiring, so we should
		// always cancel the timer and then possibly restart it below.
		if b.nmExpiryTimer != nil {
			// Ignore if we can't stop; the atomic check in the
			// AfterFunc (below) will skip running.
			b.nmExpiryTimer.Stop()

			// Nil so we don't attempt to stop on the next netmap
			b.nmExpiryTimer = nil
		}

		// Figure out when the next node in the netmap is expiring so we can
		// start a timer to reconfigure at that point.
		nextExpiry := b.em.nextPeerExpiry(st.NetMap, now)
		if !nextExpiry.IsZero() {
			tmrDuration := nextExpiry.Sub(now) + 10*time.Second
			b.nmExpiryTimer = b.clock.AfterFunc(tmrDuration, func() {
				// Skip if the world has moved on past the
				// saved call (e.g. if we race stopping this
				// timer).
				if b.numClientStatusCalls.Load() != currCall {
					return
				}

				b.logf("setClientStatus: netmap expiry timer triggered after %v", tmrDuration)

				// Call ourselves with the current status again; the logic in
				// setClientStatus will take care of updating the expired field
				// of peers in the netmap.
				b.SetControlClientStatus(c, st)
			})
		}
	}

	wasBlocked := b.blocked
	keyExpiryExtended := false
	if st.NetMap != nil {
		wasExpired := b.keyExpired
		isExpired := !st.NetMap.Expiry.IsZero() && st.NetMap.Expiry.Before(b.clock.Now())
		if wasExpired && !isExpired {
			keyExpiryExtended = true
		}
		b.keyExpired = isExpired
	}

	unlock.UnlockEarly()

	if keyExpiryExtended && wasBlocked {
		// Key extended, unblock the engine
		b.blockEngineUpdates(false)
	}

	if st.LoginFinished() && (wasBlocked || b.seamlessRenewalEnabled()) {
		if wasBlocked {
			// Auth completed, unblock the engine
			b.blockEngineUpdates(false)
		}
		b.authReconfig()
		b.send(ipn.Notify{LoginFinished: &empty.Message{}})
	}

	// Lock b again and do only the things that require locking.
	b.mu.Lock()

	prefsChanged := false
	prefs := b.pm.CurrentPrefs().AsStruct()
	oldNetMap := b.netMap
	curNetMap := st.NetMap
	if curNetMap == nil {
		// The status didn't include a netmap update, so the old one is still
		// current.
		curNetMap = oldNetMap
	}

	if prefs.ControlURL == "" {
		// Once we get a message from the control plane, set
		// our ControlURL pref explicitly. This causes a
		// future "tailscale up" to start checking for
		// implicit setting reverts, which it doesn't do when
		// ControlURL is blank.
		prefs.ControlURL = prefs.ControlURLOrDefault()
		prefsChanged = true
	}
	if st.Persist.Valid() {
		if !prefs.Persist.View().Equals(st.Persist) {
			prefsChanged = true
			prefs.Persist = st.Persist.AsStruct()
		}
	}
	if st.LoginFinished() {
		if b.authURL != "" {
			b.resetAuthURLLocked()
			// Interactive login finished successfully (URL visited).
			// After an interactive login, the user always wants
			// WantRunning.
			if !prefs.WantRunning {
				prefs.WantRunning = true
				prefsChanged = true
			}
		}
		if prefs.LoggedOut {
			prefs.LoggedOut = false
			prefsChanged = true
		}
	}
	if shouldAutoExitNode() {
		// Re-evaluate exit node suggestion in case circumstances have changed.
		_, err := b.suggestExitNodeLocked(curNetMap)
		if err != nil && !errors.Is(err, ErrNoPreferredDERP) {
			b.logf("SetControlClientStatus failed to select auto exit node: %v", err)
		}
	}
	if applySysPolicy(prefs, b.lastSuggestedExitNode) {
		prefsChanged = true
	}
	if setExitNodeID(prefs, curNetMap) {
		prefsChanged = true
	}

	// Until recently, we did not store the account's tailnet name. So check if this is the case,
	// and backfill it on incoming status update.
	if b.pm.requiresBackfill() && st.NetMap != nil && st.NetMap.Domain != "" {
		prefsChanged = true
	}

	// Perform all mutations of prefs based on the netmap here.
	if prefsChanged {
		// Prefs will be written out if stale; this is not safe unless locked or cloned.
		if err := b.pm.SetPrefs(prefs.View(), ipn.NetworkProfile{
			MagicDNSName: curNetMap.MagicDNSSuffix(),
			DomainName:   curNetMap.DomainName(),
		}); err != nil {
			b.logf("Failed to save new controlclient state: %v", err)
		}
	}
	// initTKALocked is dependent on CurrentProfile.ID, which is initialized
	// (for new profiles) on the first call to b.pm.SetPrefs.
	if err := b.initTKALocked(); err != nil {
		b.logf("initTKALocked: %v", err)
	}

	// Perform all reconfiguration based on the netmap here.
	if st.NetMap != nil {
		b.capTailnetLock = st.NetMap.HasCap(tailcfg.CapabilityTailnetLock)

		// As we stepped outside of the lock, it's possible for b.cc
		// to now be nil.
		if b.cc != nil {
			b.cc.SetTKAHead("")
		}

		b.setNetMapLocked(st.NetMap)
		b.updateFilterLocked(st.NetMap, prefs.View())
	}
	b.mu.Unlock()

	// Now complete the lock-free parts of what we started while locked.
	if prefsChanged {
		b.send(ipn.Notify{Prefs: ptr.To(prefs.View())})
	}

	if st.NetMap != nil {
		if envknob.NoLogsNoSupport() && st.NetMap.HasCap(tailcfg.CapabilityDataPlaneAuditLogs) {
			msg := "tailnet requires logging to be enabled. Remove --no-logs-no-support from tailscaled command line."
			b.health.SetLocalLogConfigHealth(errors.New(msg))
			// Connecting to this tailnet without logging is forbidden; boot us outta here.
			b.mu.Lock()
			prefs.WantRunning = false
			p := prefs.View()
			if err := b.pm.SetPrefs(p, ipn.NetworkProfile{
				MagicDNSName: st.NetMap.MagicDNSSuffix(),
				DomainName:   st.NetMap.DomainName(),
			}); err != nil {
				b.logf("Failed to save new controlclient state: %v", err)
			}
			b.mu.Unlock()
			b.send(ipn.Notify{ErrMessage: &msg, Prefs: &p})
			return
		}
		if oldNetMap != nil {
			diff := st.NetMap.ConciseDiffFrom(oldNetMap)
			if strings.TrimSpace(diff) == "" {
				b.logf("[v1] netmap diff: (none)")
			} else {
				b.logf("[v1] netmap diff:\n%v", diff)
			}
		}

		b.e.SetNetworkMap(st.NetMap)
		b.MagicConn().SetDERPMap(st.NetMap.DERPMap)
		b.MagicConn().SetOnlyTCP443(st.NetMap.HasCap(tailcfg.NodeAttrOnlyTCP443))

		// Update the DERP map in the health package, which uses it for health notifications
		b.health.SetDERPMap(st.NetMap.DERPMap)

		b.send(ipn.Notify{NetMap: st.NetMap})
	}
	if st.URL != "" {
		b.logf("Received auth URL: %.20v...", st.URL)
		b.setAuthURL(st.URL)
	}
	b.stateMachine()
	// This is currently (2020-07-28) necessary; conditionally disabling it is fragile!
	// This is where netmap information gets propagated to router and magicsock.
	b.authReconfig()
}

type preferencePolicyInfo struct {
	key syspolicy.Key
	get func(ipn.PrefsView) bool
	set func(*ipn.Prefs, bool)
}

var preferencePolicies = []preferencePolicyInfo{
	{
		key: syspolicy.EnableIncomingConnections,
		// Allow Incoming (used by the UI) is the negation of ShieldsUp (used by the
		// backend), so this has to convert between the two conventions.
		get: func(p ipn.PrefsView) bool { return !p.ShieldsUp() },
		set: func(p *ipn.Prefs, v bool) { p.ShieldsUp = !v },
	},
	{
		key: syspolicy.EnableServerMode,
		get: func(p ipn.PrefsView) bool { return p.ForceDaemon() },
		set: func(p *ipn.Prefs, v bool) { p.ForceDaemon = v },
	},
	{
		key: syspolicy.ExitNodeAllowLANAccess,
		get: func(p ipn.PrefsView) bool { return p.ExitNodeAllowLANAccess() },
		set: func(p *ipn.Prefs, v bool) { p.ExitNodeAllowLANAccess = v },
	},
	{
		key: syspolicy.EnableTailscaleDNS,
		get: func(p ipn.PrefsView) bool { return p.CorpDNS() },
		set: func(p *ipn.Prefs, v bool) { p.CorpDNS = v },
	},
	{
		key: syspolicy.EnableTailscaleSubnets,
		get: func(p ipn.PrefsView) bool { return p.RouteAll() },
		set: func(p *ipn.Prefs, v bool) { p.RouteAll = v },
	},
	{
		key: syspolicy.CheckUpdates,
		get: func(p ipn.PrefsView) bool { return p.AutoUpdate().Check },
		set: func(p *ipn.Prefs, v bool) { p.AutoUpdate.Check = v },
	},
	{
		key: syspolicy.ApplyUpdates,
		get: func(p ipn.PrefsView) bool { v, _ := p.AutoUpdate().Apply.Get(); return v },
		set: func(p *ipn.Prefs, v bool) { p.AutoUpdate.Apply.Set(v) },
	},
	{
		key: syspolicy.EnableRunExitNode,
		get: func(p ipn.PrefsView) bool { return p.AdvertisesExitNode() },
		set: func(p *ipn.Prefs, v bool) { p.SetAdvertiseExitNode(v) },
	},
}

// applySysPolicy overwrites configured preferences with policies that may be
// configured by the system administrator in an OS-specific way.
func applySysPolicy(prefs *ipn.Prefs, lastSuggestedExitNode tailcfg.StableNodeID) (anyChange bool) {
	if controlURL, err := syspolicy.GetString(syspolicy.ControlURL, prefs.ControlURL); err == nil && prefs.ControlURL != controlURL {
		prefs.ControlURL = controlURL
		anyChange = true
	}

	if exitNodeIDStr, _ := syspolicy.GetString(syspolicy.ExitNodeID, ""); exitNodeIDStr != "" {
		exitNodeID := tailcfg.StableNodeID(exitNodeIDStr)
		if shouldAutoExitNode() && lastSuggestedExitNode != "" {
			exitNodeID = lastSuggestedExitNode
		}
		// Note: when exitNodeIDStr == "auto" && lastSuggestedExitNode == "",
		// then exitNodeID is now "auto" which will never match a peer's node ID.
		// When there is no a peer matching the node ID, traffic will blackhole,
		// preventing accidental non-exit-node usage when a policy is in effect that requires an exit node.
		if prefs.ExitNodeID != exitNodeID || prefs.ExitNodeIP.IsValid() {
			anyChange = true
		}
		prefs.ExitNodeID = exitNodeID
		prefs.ExitNodeIP = netip.Addr{}
	} else if exitNodeIPStr, _ := syspolicy.GetString(syspolicy.ExitNodeIP, ""); exitNodeIPStr != "" {
		exitNodeIP, err := netip.ParseAddr(exitNodeIPStr)
		if exitNodeIP.IsValid() && err == nil {
			if prefs.ExitNodeID != "" || prefs.ExitNodeIP != exitNodeIP {
				anyChange = true
			}
			prefs.ExitNodeID = ""
			prefs.ExitNodeIP = exitNodeIP
		}
	}

	for _, opt := range preferencePolicies {
		if po, err := syspolicy.GetPreferenceOption(opt.key); err == nil {
			curVal := opt.get(prefs.View())
			newVal := po.ShouldEnable(curVal)
			if curVal != newVal {
				opt.set(prefs, newVal)
				anyChange = true
			}
		}
	}

	return anyChange
}

// registerSysPolicyWatch subscribes to syspolicy change notifications
// and immediately applies the effective syspolicy settings to the current profile.
func (b *LocalBackend) registerSysPolicyWatch() (unregister func(), err error) {
	if unregister, err = syspolicy.RegisterChangeCallback(b.sysPolicyChanged); err != nil {
		return nil, fmt.Errorf("syspolicy: LocalBacked failed to register policy change callback: %v", err)
	}
	if prefs, anyChange := b.applySysPolicy(); anyChange {
		b.logf("syspolicy: changed initial profile prefs: %v", prefs.Pretty())
	}
	b.refreshAllowedSuggestions()
	return unregister, nil
}

// applySysPolicy overwrites the current profile's preferences with policies
// that may be configured by the system administrator in an OS-specific way.
//
// b.mu must not be held.
func (b *LocalBackend) applySysPolicy() (_ ipn.PrefsView, anyChange bool) {
	unlock := b.lockAndGetUnlock()
	prefs := b.pm.CurrentPrefs().AsStruct()
	if !applySysPolicy(prefs, b.lastSuggestedExitNode) {
		unlock.UnlockEarly()
		return prefs.View(), false
	}
	return b.setPrefsLockedOnEntry(prefs, unlock), true
}

// sysPolicyChanged is a callback triggered by syspolicy when it detects
// a change in one or more syspolicy settings.
func (b *LocalBackend) sysPolicyChanged(policy *rsop.PolicyChange) {
	if policy.HasChanged(syspolicy.AllowedSuggestedExitNodes) {
		b.refreshAllowedSuggestions()
		// Re-evaluate exit node suggestion now that the policy setting has changed.
		b.mu.Lock()
		_, err := b.suggestExitNodeLocked(nil)
		b.mu.Unlock()
		if err != nil && !errors.Is(err, ErrNoPreferredDERP) {
			b.logf("failed to select auto exit node: %v", err)
		}
		// If [syspolicy.ExitNodeID] is set to `auto:any`, the suggested exit node ID
		// will be used when [applySysPolicy] updates the current profile's prefs.
	}

	if prefs, anyChange := b.applySysPolicy(); anyChange {
		b.logf("syspolicy: changed profile prefs: %v", prefs.Pretty())
	}
}

var _ controlclient.NetmapDeltaUpdater = (*LocalBackend)(nil)

// UpdateNetmapDelta implements controlclient.NetmapDeltaUpdater.
func (b *LocalBackend) UpdateNetmapDelta(muts []netmap.NodeMutation) (handled bool) {
	if !b.MagicConn().UpdateNetmapDelta(muts) {
		return false
	}

	var notify *ipn.Notify // non-nil if we need to send a Notify
	defer func() {
		if notify != nil {
			b.send(*notify)
		}
	}()
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.updateNetmapDeltaLocked(muts) {
		return false
	}

	if b.netMap != nil && mutationsAreWorthyOfTellingIPNBus(muts) {
		nm := ptr.To(*b.netMap) // shallow clone
		nm.Peers = make([]tailcfg.NodeView, 0, len(b.peers))
		for _, p := range b.peers {
			nm.Peers = append(nm.Peers, p)
		}
		slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
			return cmp.Compare(a.ID(), b.ID())
		})
		notify = &ipn.Notify{NetMap: nm}
	} else if testenv.InTest() {
		// In tests, send an empty Notify as a wake-up so end-to-end
		// integration tests in another repo can check on the status of
		// LocalBackend after processing deltas.
		notify = new(ipn.Notify)
	}
	return true
}

// mutationsAreWorthyOfTellingIPNBus reports whether any mutation type in muts is
// worthy of spamming the IPN bus (the Windows & Mac GUIs, basically) to tell them
// about the update.
func mutationsAreWorthyOfTellingIPNBus(muts []netmap.NodeMutation) bool {
	for _, m := range muts {
		switch m.(type) {
		case netmap.NodeMutationLastSeen,
			netmap.NodeMutationOnline:
			// The GUI clients might render peers differently depending on whether
			// they're online.
			return true
		}
	}
	return false
}

// pickNewAutoExitNode picks a new automatic exit node if needed.
func (b *LocalBackend) pickNewAutoExitNode() {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	newPrefs := b.setAutoExitNodeIDLockedOnEntry(unlock)
	if !newPrefs.Valid() {
		// Unchanged.
		return
	}

	b.send(ipn.Notify{Prefs: &newPrefs})
}

func (b *LocalBackend) updateNetmapDeltaLocked(muts []netmap.NodeMutation) (handled bool) {
	if b.netMap == nil || len(b.peers) == 0 {
		return false
	}

	// Locally cloned mutable nodes, to avoid calling AsStruct (clone)
	// multiple times on a node if it's mutated multiple times in this
	// call (e.g. its endpoints + online status both change)
	var mutableNodes map[tailcfg.NodeID]*tailcfg.Node

	for _, m := range muts {
		n, ok := mutableNodes[m.NodeIDBeingMutated()]
		if !ok {
			nv, ok := b.peers[m.NodeIDBeingMutated()]
			if !ok {
				// TODO(bradfitz): unexpected metric?
				return false
			}
			n = nv.AsStruct()
			mak.Set(&mutableNodes, nv.ID(), n)
		}
		m.Apply(n)

		// If our exit node went offline, we need to schedule picking
		// a new one.
		if mo, ok := m.(netmap.NodeMutationOnline); ok && !mo.Online && n.StableID == b.pm.prefs.ExitNodeID() && shouldAutoExitNode() {
			b.goTracker.Go(b.pickNewAutoExitNode)
		}
	}
	for nid, n := range mutableNodes {
		b.peers[nid] = n.View()
	}
	return true
}

// setExitNodeID updates prefs to reference an exit node by ID, rather
// than by IP. It returns whether prefs was mutated.
func setExitNodeID(prefs *ipn.Prefs, nm *netmap.NetworkMap) (prefsChanged bool) {
	if nm == nil {
		// No netmap, can't resolve anything.
		return false
	}

	// If we have a desired IP on file, try to find the corresponding
	// node.
	if !prefs.ExitNodeIP.IsValid() {
		return false
	}

	// IP takes precedence over ID, so if both are set, clear ID.
	if prefs.ExitNodeID != "" {
		prefs.ExitNodeID = ""
		prefsChanged = true
	}

	oldExitNodeID := prefs.ExitNodeID
	for _, peer := range nm.Peers {
		for _, addr := range peer.Addresses().All() {
			if !addr.IsSingleIP() || addr.Addr() != prefs.ExitNodeIP {
				continue
			}
			// Found the node being referenced, upgrade prefs to
			// reference it directly for next time.
			prefs.ExitNodeID = peer.StableID()
			prefs.ExitNodeIP = netip.Addr{}
			return prefsChanged || oldExitNodeID != prefs.ExitNodeID
		}
	}

	return prefsChanged
}

// setWgengineStatus is the callback by the wireguard engine whenever it posts a new status.
// This updates the endpoints both in the backend and in the control client.
func (b *LocalBackend) setWgengineStatus(s *wgengine.Status, err error) {
	if err != nil {
		b.logf("wgengine status error: %v", err)
		b.broadcastStatusChanged()
		return
	}
	if s == nil {
		b.logf("[unexpected] non-error wgengine update with status=nil: %v", s)
		b.broadcastStatusChanged()
		return
	}

	b.mu.Lock()
	if s.AsOf.Before(b.lastStatusTime) {
		// Don't process a status update that is older than the one we have
		// already processed. (corp#2579)
		b.mu.Unlock()
		return
	}
	b.lastStatusTime = s.AsOf
	es := b.parseWgStatusLocked(s)
	cc := b.cc
	b.engineStatus = es
	needUpdateEndpoints := !endpointsEqual(s.LocalAddrs, b.endpoints)
	if needUpdateEndpoints {
		b.endpoints = append([]tailcfg.Endpoint{}, s.LocalAddrs...)
	}
	b.mu.Unlock()

	if cc != nil {
		if needUpdateEndpoints {
			cc.UpdateEndpoints(s.LocalAddrs)
		}
		b.stateMachine()
	}
	b.broadcastStatusChanged()
	b.send(ipn.Notify{Engine: &es})
}

func (b *LocalBackend) broadcastStatusChanged() {
	// The sync.Cond docs say: "It is allowed but not required for the caller to hold c.L during the call."
	// In this particular case, we must acquire b.statusLock. Otherwise we might broadcast before
	// the waiter (in requestEngineStatusAndWait) starts to wait, in which case
	// the waiter can get stuck indefinitely. See PR 2865.
	b.statusLock.Lock()
	b.statusChanged.Broadcast()
	b.statusLock.Unlock()
}

func endpointsEqual(x, y []tailcfg.Endpoint) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// SetNotifyCallback sets the function to call when the backend has something to
// notify the frontend about. Only one callback can be set at a time, so calling
// this function will replace the previous callback.
func (b *LocalBackend) SetNotifyCallback(notify func(ipn.Notify)) {
	ctx, cancel := context.WithCancel(b.ctx)
	b.mu.Lock()
	prevCancel := b.notifyCancel
	b.notifyCancel = cancel
	b.mu.Unlock()
	if prevCancel != nil {
		prevCancel()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go b.WatchNotifications(ctx, 0, wg.Done, func(n *ipn.Notify) bool {
		notify(*n)
		return true
	})
	wg.Wait()
}

// SetHTTPTestClient sets an alternate HTTP client to use with
// connections to the coordination server. It exists for
// testing. Using nil means to use the default.
func (b *LocalBackend) SetHTTPTestClient(c *http.Client) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.httpTestClient = c
}

// SetControlClientGetterForTesting sets the func that creates a
// control plane client. It can be called at most once, before Start.
func (b *LocalBackend) SetControlClientGetterForTesting(newControlClient func(controlclient.Options) (controlclient.Client, error)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ccGen != nil {
		panic("invalid use of SetControlClientGetterForTesting after Start")
	}
	b.ccGen = newControlClient
}

// NodeViewByIDForTest returns the state of the node with the given ID
// for integration tests in another repo.
func (b *LocalBackend) NodeViewByIDForTest(id tailcfg.NodeID) (_ tailcfg.NodeView, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok := b.peers[id]
	return n, ok
}

// DisablePortMapperForTest disables the portmapper for tests.
// It must be called before Start.
func (b *LocalBackend) DisablePortMapperForTest() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.portpoll = nil
}

// PeersForTest returns all the current peers, sorted by Node.ID,
// for integration tests in another repo.
func (b *LocalBackend) PeersForTest() []tailcfg.NodeView {
	b.mu.Lock()
	defer b.mu.Unlock()
	ret := slicesx.MapValues(b.peers)
	slices.SortFunc(ret, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	return ret
}

func (b *LocalBackend) getNewControlClientFuncLocked() clientGen {
	if b.ccGen == nil {
		// Initialize it rather than just returning the
		// default to make any future call to
		// SetControlClientGetterForTesting panic.
		b.ccGen = func(opts controlclient.Options) (controlclient.Client, error) {
			return controlclient.New(opts)
		}
	}
	return b.ccGen
}

// Start applies the configuration specified in opts, and starts the
// state machine.
//
// TODO(danderson): this function is trying to do too many things at
// once: it loads state, or imports it, or updates prefs sometimes,
// contains some settings that are one-shot things done by `tailscale
// up` because we had nowhere else to put them, and there's no clear
// guarantee that switching from one user's state to another is
// actually a supported operation (it should be, but it's very unclear
// from the following whether or not that is a safe transition).
func (b *LocalBackend) Start(opts ipn.Options) error {
	b.logf("Start")

	var clientToShutdown controlclient.Client
	defer func() {
		if clientToShutdown != nil {
			clientToShutdown.Shutdown()
		}
	}()
	unlock := b.lockAndGetUnlock()
	defer unlock()

	if opts.UpdatePrefs != nil {
		if err := b.checkPrefsLocked(opts.UpdatePrefs); err != nil {
			return err
		}
	}
	if b.state != ipn.Running && b.conf != nil && b.conf.Parsed.AuthKey != nil && opts.AuthKey == "" {
		v := *b.conf.Parsed.AuthKey
		if filename, ok := strings.CutPrefix(v, "file:"); ok {
			b, err := os.ReadFile(filename)
			if err != nil {
				return fmt.Errorf("error reading config file authKey: %w", err)
			}
			v = strings.TrimSpace(string(b))
		}
		opts.AuthKey = v
	}

	if b.state != ipn.Running && b.conf == nil && opts.AuthKey == "" {
		sysak, _ := syspolicy.GetString(syspolicy.AuthKey, "")
		if sysak != "" {
			b.logf("Start: setting opts.AuthKey by syspolicy, len=%v", len(sysak))
			opts.AuthKey = strings.TrimSpace(sysak)
		}
	}

	hostinfo := hostinfo.New()
	applyConfigToHostinfo(hostinfo, b.conf)
	hostinfo.BackendLogID = b.backendLogID.String()
	hostinfo.FrontendLogID = opts.FrontendLogID
	hostinfo.Userspace.Set(b.sys.IsNetstack())
	hostinfo.UserspaceRouter.Set(b.sys.IsNetstackRouter())
	b.logf.JSON(1, "Hostinfo", hostinfo)

	// TODO(apenwarr): avoid the need to reinit controlclient.
	// This will trigger a full relogin/reconfigure cycle every
	// time a Handle reconnects to the backend. Ideally, we
	// would send the new Prefs and everything would get back
	// into sync with the minimal changes. But that's not how it
	// is right now, which is a sign that the code is still too
	// complicated.
	clientToShutdown = b.resetControlClientLocked()
	httpTestClient := b.httpTestClient

	if b.hostinfo != nil {
		hostinfo.Services = b.hostinfo.Services // keep any previous services
	}
	b.hostinfo = hostinfo
	b.state = ipn.NoState

	if opts.UpdatePrefs != nil {
		oldPrefs := b.pm.CurrentPrefs()
		newPrefs := opts.UpdatePrefs.Clone()
		newPrefs.Persist = oldPrefs.Persist().AsStruct()
		pv := newPrefs.View()
		if err := b.pm.SetPrefs(pv, ipn.NetworkProfile{
			MagicDNSName: b.netMap.MagicDNSSuffix(),
			DomainName:   b.netMap.DomainName(),
		}); err != nil {
			b.logf("failed to save UpdatePrefs state: %v", err)
		}
		b.setAtomicValuesFromPrefsLocked(pv)
	} else {
		b.setAtomicValuesFromPrefsLocked(b.pm.CurrentPrefs())
	}

	prefs := b.pm.CurrentPrefs()
	wantRunning := prefs.WantRunning()
	if wantRunning {
		if err := b.initMachineKeyLocked(); err != nil {
			return fmt.Errorf("initMachineKeyLocked: %w", err)
		}
	}

	loggedOut := prefs.LoggedOut()

	serverURL := prefs.ControlURLOrDefault()
	if inServerMode := prefs.ForceDaemon(); inServerMode || runtime.GOOS == "windows" {
		b.logf("Start: serverMode=%v", inServerMode)
	}
	b.applyPrefsToHostinfoLocked(hostinfo, prefs)

	b.setNetMapLocked(nil)
	persistv := prefs.Persist().AsStruct()
	if persistv == nil {
		persistv = new(persist.Persist)
	}
	b.updateFilterLocked(nil, ipn.PrefsView{})

	if b.portpoll != nil {
		b.portpollOnce.Do(func() {
			b.goTracker.Go(b.readPoller)
		})
	}

	discoPublic := b.MagicConn().DiscoPublicKey()

	var err error

	isNetstack := b.sys.IsNetstackRouter()
	debugFlags := controlDebugFlags
	if isNetstack {
		debugFlags = append([]string{"netstack"}, debugFlags...)
	}

	// TODO(apenwarr): The only way to change the ServerURL is to
	// re-run b.Start, because this is the only place we create a
	// new controlclient. EditPrefs allows you to overwrite ServerURL,
	// but it won't take effect until the next Start.
	cc, err := b.getNewControlClientFuncLocked()(controlclient.Options{
		GetMachinePrivateKey:       b.createGetMachinePrivateKeyFunc(),
		Logf:                       logger.WithPrefix(b.logf, "control: "),
		Persist:                    *persistv,
		ServerURL:                  serverURL,
		AuthKey:                    opts.AuthKey,
		Hostinfo:                   hostinfo,
		HTTPTestClient:             httpTestClient,
		DiscoPublicKey:             discoPublic,
		DebugFlags:                 debugFlags,
		HealthTracker:              b.health,
		Pinger:                     b,
		PopBrowserURL:              b.tellClientToBrowseToURL,
		OnClientVersion:            b.onClientVersion,
		OnTailnetDefaultAutoUpdate: b.onTailnetDefaultAutoUpdate,
		OnControlTime:              b.em.onControlTime,
		Dialer:                     b.Dialer(),
		Observer:                   b,
		C2NHandler:                 http.HandlerFunc(b.handleC2N),
		DialPlan:                   &b.dialPlan, // pointer because it can't be copied
		ControlKnobs:               b.sys.ControlKnobs(),

		// Don't warn about broken Linux IP forwarding when
		// netstack is being used.
		SkipIPForwardingCheck: isNetstack,
	})
	if err != nil {
		return err
	}

	b.setControlClientLocked(cc)
	endpoints := b.endpoints

	if err := b.initTKALocked(); err != nil {
		b.logf("initTKALocked: %v", err)
	}
	var tkaHead string
	confWantRunning := b.conf != nil && wantRunning

	if endpoints != nil {
		cc.UpdateEndpoints(endpoints)
	}
	cc.SetTKAHead(tkaHead)

	blid := b.backendLogID.String()
	b.logf("Backend: logs: be:%v fe:%v", blid, opts.FrontendLogID)
	b.sendToLocked(ipn.Notify{Prefs: &prefs}, allClients)

	if !loggedOut && (b.hasNodeKeyLocked() || confWantRunning) {
		// If we know that we're either logged in or meant to be
		// running, tell the controlclient that it should also assume
		// that we need to be logged in.
		//
		// Without this, the state machine transitions to "NeedsLogin" implying
		// that user interaction is required, which is not the case and can
		// regress tsnet.Server restarts.
		cc.Login(controlclient.LoginDefault)
	}
	b.stateMachineLockedOnEntry(unlock)

	return nil
}

// invalidPacketFilterWarnable is a Warnable to warn the user that the control server sent an invalid packet filter.
var invalidPacketFilterWarnable = health.Register(&health.Warnable{
	Code:     "invalid-packet-filter",
	Title:    "Invalid packet filter",
	Severity: health.SeverityHigh,
	Text:     health.StaticMessage("The coordination server sent an invalid packet filter permitting traffic to unlocked nodes; rejecting all packets for safety"),
})

// updateFilterLocked updates the packet filter in wgengine based on the
// given netMap and user preferences.
//
// b.mu must be held.
func (b *LocalBackend) updateFilterLocked(netMap *netmap.NetworkMap, prefs ipn.PrefsView) {
	// NOTE(danderson): keep change detection as the first thing in
	// this function. Don't try to optimize by returning early, more
	// likely than not you'll just end up breaking the change
	// detection and end up with the wrong filter installed. This is
	// quite hard to debug, so save yourself the trouble.
	var (
		haveNetmap   = netMap != nil
		addrs        views.Slice[netip.Prefix]
		packetFilter []filter.Match
		localNetsB   netipx.IPSetBuilder
		logNetsB     netipx.IPSetBuilder
		shieldsUp    = !prefs.Valid() || prefs.ShieldsUp() // Be conservative when not ready
	)
	// Log traffic for Tailscale IPs.
	logNetsB.AddPrefix(tsaddr.CGNATRange())
	logNetsB.AddPrefix(tsaddr.TailscaleULARange())
	logNetsB.RemovePrefix(tsaddr.ChromeOSVMRange())
	if haveNetmap {
		addrs = netMap.GetAddresses()
		for i := range addrs.Len() {
			localNetsB.AddPrefix(addrs.At(i))
		}
		packetFilter = netMap.PacketFilter

		if packetFilterPermitsUnlockedNodes(b.peers, packetFilter) {
			b.health.SetUnhealthy(invalidPacketFilterWarnable, nil)
			packetFilter = nil
		} else {
			b.health.SetHealthy(invalidPacketFilterWarnable)
		}
	}
	if prefs.Valid() {
		for _, r := range prefs.AdvertiseRoutes().All() {
			if r.Bits() == 0 {
				// When offering a default route to the world, we
				// filter out locally reachable LANs, so that the
				// default route effectively appears to be a "guest
				// wifi": you get internet access, but to additionally
				// get LAN access the LAN(s) need to be offered
				// explicitly as well.
				localInterfaceRoutes, hostIPs, err := interfaceRoutes()
				if err != nil {
					b.logf("getting local interface routes: %v", err)
					continue
				}
				s, err := shrinkDefaultRoute(r, localInterfaceRoutes, hostIPs)
				if err != nil {
					b.logf("computing default route filter: %v", err)
					continue
				}
				localNetsB.AddSet(s)
			} else {
				localNetsB.AddPrefix(r)
				// When advertising a non-default route, we assume
				// this is a corporate subnet that should be present
				// in the audit logs.
				logNetsB.AddPrefix(r)
			}
		}

		// App connectors handle DNS requests for app domains over PeerAPI (corp#11961),
		// but a safety check verifies the requesting peer has at least permission
		// to send traffic to 0.0.0.0:53 (or 2000:: for IPv6) before handling the DNS
		// request (see peerAPIHandler.replyToDNSQueries in peerapi.go).
		// The correct filter rules are synthesized by the coordination server
		// and sent down, but the address needs to be part of the 'local net' for the
		// filter package to even bother checking the filter rules, so we set them here.
		if prefs.AppConnector().Advertise {
			localNetsB.Add(netip.MustParseAddr("0.0.0.0"))
			localNetsB.Add(netip.MustParseAddr("::0"))
		}
	}
	localNets, _ := localNetsB.IPSet()
	logNets, _ := logNetsB.IPSet()
	var sshPol tailcfg.SSHPolicy
	if haveNetmap && netMap.SSHPolicy != nil {
		sshPol = *netMap.SSHPolicy
	}

	changed := deephash.Update(&b.filterHash, &struct {
		HaveNetmap  bool
		Addrs       views.Slice[netip.Prefix]
		FilterMatch []filter.Match
		LocalNets   []netipx.IPRange
		LogNets     []netipx.IPRange
		ShieldsUp   bool
		SSHPolicy   tailcfg.SSHPolicy
	}{haveNetmap, addrs, packetFilter, localNets.Ranges(), logNets.Ranges(), shieldsUp, sshPol})
	if !changed {
		return
	}

	if !haveNetmap {
		b.logf("[v1] netmap packet filter: (not ready yet)")
		noneFilter := filter.NewAllowNone(b.logf, logNets)
		b.setFilter(noneFilter)
		b.e.SetJailedFilter(noneFilter)
		return
	}

	oldFilter := b.e.GetFilter()
	if shieldsUp {
		b.logf("[v1] netmap packet filter: (shields up)")
		b.setFilter(filter.NewShieldsUpFilter(localNets, logNets, oldFilter, b.logf))
	} else {
		b.logf("[v1] netmap packet filter: %v filters", len(packetFilter))
		b.setFilter(filter.New(packetFilter, b.srcIPHasCapForFilter, localNets, logNets, oldFilter, b.logf))
	}
	// The filter for a jailed node is the exact same as a ShieldsUp filter.
	oldJailedFilter := b.e.GetJailedFilter()
	b.e.SetJailedFilter(filter.NewShieldsUpFilter(localNets, logNets, oldJailedFilter, b.logf))

	if b.sshServer != nil {
		b.goTracker.Go(b.sshServer.OnPolicyChange)
	}
}

// captivePortalWarnable is a Warnable which is set to an unhealthy state when a captive portal is detected.
var captivePortalWarnable = health.Register(&health.Warnable{
	Code:  "captive-portal-detected",
	Title: "Captive portal detected",
	// High severity, because captive portals block all traffic and require user intervention.
	Severity:            health.SeverityHigh,
	Text:                health.StaticMessage("This network requires you to log in using your web browser."),
	ImpactsConnectivity: true,
})

func (b *LocalBackend) checkCaptivePortalLoop(ctx context.Context) {
	var tmr *time.Timer

	maybeStartTimer := func() {
		// If there's an existing timer, nothing to do; just continue
		// waiting for it to expire. Otherwise, create a new timer.
		if tmr == nil {
			tmr = time.NewTimer(captivePortalDetectionInterval)
		}
	}
	maybeStopTimer := func() {
		if tmr == nil {
			return
		}
		if !tmr.Stop() {
			<-tmr.C
		}
		tmr = nil
	}

	for {
		if ctx.Err() != nil {
			maybeStopTimer()
			return
		}

		// First, see if we have a signal on our "healthy" channel, which
		// takes priority over an existing timer. Because a select is
		// nondeterministic, we explicitly check this channel before
		// entering the main select below, so that we're guaranteed to
		// stop the timer before starting captive portal detection.
		select {
		case needsCaptiveDetection := <-b.needsCaptiveDetection:
			if needsCaptiveDetection {
				maybeStartTimer()
			} else {
				maybeStopTimer()
			}
		default:
		}

		var timerChan <-chan time.Time
		if tmr != nil {
			timerChan = tmr.C
		}
		select {
		case <-ctx.Done():
			// All done; stop the timer and then exit.
			maybeStopTimer()
			return
		case <-timerChan:
			// Kick off captive portal check
			b.performCaptiveDetection()
			// nil out timer to force recreation
			tmr = nil
		case needsCaptiveDetection := <-b.needsCaptiveDetection:
			if needsCaptiveDetection {
				maybeStartTimer()
			} else {
				// Healthy; cancel any existing timer
				maybeStopTimer()
			}
		}
	}
}

// performCaptiveDetection checks if captive portal detection is enabled via controlknob. If so, it runs
// the detection and updates the Warnable accordingly.
func (b *LocalBackend) performCaptiveDetection() {
}

// shouldRunCaptivePortalDetection reports whether capgtive portal detection
// should be run. It is enabled by default, but can be disabled via a control
// knob. It is also only run when the user explicitly wants the backend to be
// running.
func (b *LocalBackend) shouldRunCaptivePortalDetection() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.ControlKnobs().DisableCaptivePortalDetection.Load() && b.pm.prefs.WantRunning()
}

// packetFilterPermitsUnlockedNodes reports any peer in peers with the
// UnsignedPeerAPIOnly bool set true has any of its allowed IPs in the packet
// filter.
//
// If this reports true, the packet filter is invalid (the server is either broken
// or malicious) and should be ignored for safety.
func packetFilterPermitsUnlockedNodes(peers map[tailcfg.NodeID]tailcfg.NodeView, packetFilter []filter.Match) bool {
	var b netipx.IPSetBuilder
	var numUnlocked int
	for _, p := range peers {
		if !p.UnsignedPeerAPIOnly() {
			continue
		}
		numUnlocked++
		for _, pfx := range p.AllowedIPs().All() { // not only addresses!
			b.AddPrefix(pfx)
		}
	}
	if numUnlocked == 0 {
		return false
	}
	s, err := b.IPSet()
	if err != nil {
		// Shouldn't happen, but if it does, fail closed.
		return true
	}
	for _, m := range packetFilter {
		for _, r := range m.Srcs {
			if !s.OverlapsPrefix(r) {
				continue
			}
			if len(m.Dsts) != 0 {
				return true
			}
		}
	}
	return false
}

func (b *LocalBackend) setFilter(f *filter.Filter) {
	b.filterAtomic.Store(f)
	b.e.SetFilter(f)
}

var removeFromDefaultRoute = []netip.Prefix{
	// RFC1918 LAN ranges
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("10.0.0.0/8"),
	// IPv4 link-local
	netip.MustParsePrefix("169.254.0.0/16"),
	// IPv4 multicast
	netip.MustParsePrefix("224.0.0.0/4"),
	// Tailscale IPv4 range
	tsaddr.CGNATRange(),
	// IPv6 Link-local addresses
	netip.MustParsePrefix("fe80::/10"),
	// IPv6 multicast
	netip.MustParsePrefix("ff00::/8"),
	// Tailscale IPv6 range
	tsaddr.TailscaleULARange(),
}

// internalAndExternalInterfaces splits interface routes into "internal"
// and "external" sets. Internal routes are those of virtual ethernet
// network interfaces used by guest VMs and containers, such as WSL and
// Docker.
//
// Given that "internal" routes don't leave the device, we choose to
// trust them more, allowing access to them when an Exit Node is enabled.
func internalAndExternalInterfaces() (internal, external []netip.Prefix, err error) {
	il, err := netmon.GetInterfaceList()
	if err != nil {
		return nil, nil, err
	}
	return internalAndExternalInterfacesFrom(il, runtime.GOOS)
}

func internalAndExternalInterfacesFrom(il netmon.InterfaceList, goos string) (internal, external []netip.Prefix, err error) {
	// We use an IPSetBuilder here to canonicalize the prefixes
	// and to remove any duplicate entries.
	var internalBuilder, externalBuilder netipx.IPSetBuilder
	if err := il.ForeachInterfaceAddress(func(iface netmon.Interface, pfx netip.Prefix) {
		if tsaddr.IsTailscaleIP(pfx.Addr()) {
			return
		}
		if pfx.IsSingleIP() {
			return
		}
		if iface.IsLoopback() {
			internalBuilder.AddPrefix(pfx)
			return
		}
		if goos == "windows" {
			// Windows Hyper-V prefixes all MAC addresses with 00:15:5d.
			// https://docs.microsoft.com/en-us/troubleshoot/windows-server/virtualization/default-limit-256-dynamic-mac-addresses
			//
			// This includes WSL2 vEthernet.
			// Importantly: by default WSL2 /etc/resolv.conf points to
			// a stub resolver running on the host vEthernet IP.
			// So enabling exit nodes with the default tailnet
			// configuration breaks WSL2 DNS without this.
			mac := iface.Interface.HardwareAddr
			if len(mac) == 6 && mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5d {
				internalBuilder.AddPrefix(pfx)
				return
			}
		}
		externalBuilder.AddPrefix(pfx)
	}); err != nil {
		return nil, nil, err
	}
	iSet, err := internalBuilder.IPSet()
	if err != nil {
		return nil, nil, err
	}
	eSet, err := externalBuilder.IPSet()
	if err != nil {
		return nil, nil, err
	}

	return iSet.Prefixes(), eSet.Prefixes(), nil
}

func interfaceRoutes() (ips *netipx.IPSet, hostIPs []netip.Addr, err error) {
	var b netipx.IPSetBuilder
	if err := netmon.ForeachInterfaceAddress(func(_ netmon.Interface, pfx netip.Prefix) {
		if tsaddr.IsTailscaleIP(pfx.Addr()) {
			return
		}
		if pfx.IsSingleIP() {
			return
		}
		hostIPs = append(hostIPs, pfx.Addr())
		b.AddPrefix(pfx)
	}); err != nil {
		return nil, nil, err
	}

	ipSet, _ := b.IPSet()
	return ipSet, hostIPs, nil
}

// shrinkDefaultRoute returns an IPSet representing the IPs in route,
// minus those in removeFromDefaultRoute and localInterfaceRoutes,
// plus the IPs in hostIPs.
func shrinkDefaultRoute(route netip.Prefix, localInterfaceRoutes *netipx.IPSet, hostIPs []netip.Addr) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	// Add the default route.
	b.AddPrefix(route)
	// Remove the local interface routes.
	b.RemoveSet(localInterfaceRoutes)

	// Having removed all the LAN subnets, re-add the hosts's own
	// IPs. It's fine for clients to connect to an exit node's public
	// IP address, just not the attached subnet.
	//
	// Truly forbidden subnets (in removeFromDefaultRoute) will still
	// be stripped back out by the next step.
	for _, ip := range hostIPs {
		if route.Contains(ip) {
			b.Add(ip)
		}
	}

	for _, pfx := range removeFromDefaultRoute {
		b.RemovePrefix(pfx)
	}
	return b.IPSet()
}

// readPoller is a goroutine that receives service lists from
// b.portpoll and propagates them into the controlclient's HostInfo.
func (b *LocalBackend) readPoller() {
	if !envknob.BoolDefaultTrue("TS_PORTLIST") {
		return
	}

	ticker, tickerChannel := b.clock.NewTicker(portlist.PollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-tickerChannel:
		case <-b.ctx.Done():
			return
		}

		if !b.shouldUploadServices() {
			continue
		}

		ports, changed, err := b.portpoll.Poll()
		if err != nil {
			b.logf("error polling for open ports: %v", err)
			return
		}
		if !changed {
			continue
		}
		sl := []tailcfg.Service{}
		for _, p := range ports {
			s := tailcfg.Service{
				Proto:       tailcfg.ServiceProto(p.Proto),
				Port:        p.Port,
				Description: p.Process,
			}
			if policy.IsInterestingService(s, version.OS()) {
				sl = append(sl, s)
			}
		}

		b.mu.Lock()
		if b.hostinfo == nil {
			b.hostinfo = new(tailcfg.Hostinfo)
		}
		b.hostinfo.Services = sl
		b.mu.Unlock()

		b.doSetHostinfoFilterServices()
	}
}

// GetPushDeviceToken returns the push notification device token.
func (b *LocalBackend) GetPushDeviceToken() string {
	return b.pushDeviceToken.Load()
}

// SetPushDeviceToken sets the push notification device token and informs the
// controlclient of the new value.
func (b *LocalBackend) SetPushDeviceToken(tk string) {
	old := b.pushDeviceToken.Swap(tk)
	if old == tk {
		return
	}
	b.doSetHostinfoFilterServices()
}

func applyConfigToHostinfo(hi *tailcfg.Hostinfo, c *conffile.Config) {
	if c == nil {
		return
	}
	if c.Parsed.Hostname != nil {
		hi.Hostname = *c.Parsed.Hostname
	}
}

// WatchNotifications subscribes to the ipn.Notify message bus notification
// messages.
//
// WatchNotifications blocks until ctx is done.
//
// The provided onWatchAdded, if non-nil, will be called once the watcher
// is installed.
//
// The provided fn will be called for each notification. It will only be
// called with non-nil pointers. The caller must not modify roNotify. If
// fn returns false, the watch also stops.
//
// Failure to consume many notifications in a row will result in dropped
// notifications. There is currently (2022-11-22) no mechanism provided to
// detect when a message has been dropped.
func (b *LocalBackend) WatchNotifications(ctx context.Context, mask ipn.NotifyWatchOpt, onWatchAdded func(), fn func(roNotify *ipn.Notify) (keepGoing bool)) {
	b.WatchNotificationsAs(ctx, nil, mask, onWatchAdded, fn)
}

// WatchNotificationsAs is like WatchNotifications but takes an [ipnauth.Actor]
// as an additional parameter. If non-nil, the specified callback is invoked
// only for notifications relevant to this actor.
func (b *LocalBackend) WatchNotificationsAs(ctx context.Context, actor ipnauth.Actor, mask ipn.NotifyWatchOpt, onWatchAdded func(), fn func(roNotify *ipn.Notify) (keepGoing bool)) {
	ch := make(chan *ipn.Notify, 128)
	sessionID := rands.HexString(16)
	origFn := fn
	if mask&ipn.NotifyNoPrivateKeys != 0 {
		fn = func(n *ipn.Notify) bool {
			if n.NetMap == nil || n.NetMap.PrivateKey.IsZero() {
				return origFn(n)
			}

			// The netmap in n is shared across all watchers, so to mutate it for a
			// single watcher we have to clone the notify and the netmap. We can
			// make shallow clones, at least.
			nm2 := *n.NetMap
			n2 := *n
			n2.NetMap = &nm2
			n2.NetMap.PrivateKey = key.NodePrivate{}
			return origFn(&n2)
		}
	}

	var ini *ipn.Notify

	b.mu.Lock()

	const initialBits = ipn.NotifyInitialState | ipn.NotifyInitialPrefs | ipn.NotifyInitialNetMap | ipn.NotifyInitialDriveShares
	if mask&initialBits != 0 {
		ini = &ipn.Notify{Version: version.Long()}
		if mask&ipn.NotifyInitialState != 0 {
			ini.SessionID = sessionID
			ini.State = ptr.To(b.state)
			if b.state == ipn.NeedsLogin && b.authURL != "" {
				ini.BrowseToURL = ptr.To(b.authURL)
			}
		}
		if mask&ipn.NotifyInitialPrefs != 0 {
			ini.Prefs = ptr.To(b.sanitizedPrefsLocked())
		}
		if mask&ipn.NotifyInitialNetMap != 0 {
			ini.NetMap = b.netMap
		}
		if mask&ipn.NotifyInitialHealthState != 0 {
			ini.Health = b.HealthTracker().CurrentState()
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	session := &watchSession{
		ch:        ch,
		owner:     actor,
		sessionID: sessionID,
		cancel:    cancel,
	}
	mak.Set(&b.notifyWatchers, sessionID, session)
	b.mu.Unlock()

	metricCurrentWatchIPNBus.Add(1)
	defer metricCurrentWatchIPNBus.Add(-1)

	defer func() {
		b.mu.Lock()
		delete(b.notifyWatchers, sessionID)
		b.mu.Unlock()
	}()

	if onWatchAdded != nil {
		onWatchAdded()
	}

	if ini != nil {
		if !fn(ini) {
			return
		}
	}

	// The GUI clients want to know when peers become active or inactive.
	// They've historically got this information by polling for it, which is
	// wasteful. As a step towards making it efficient, they now set this
	// NotifyWatchEngineUpdates bit to ask for us to send it to them only on
	// change. That's not yet (as of 2022-11-26) plumbed everywhere in
	// tailscaled yet, so just do the polling here. This ends up causing all IPN
	// bus watchers to get the notification every 2 seconds instead of just the
	// GUI client's bus watcher, but in practice there's only 1 total connection
	// anyway. And if we're polling, at least the client isn't making a new HTTP
	// request every 2 seconds.
	// TODO(bradfitz): plumb this further and only send a Notify on change.
	if mask&ipn.NotifyWatchEngineUpdates != 0 {
		b.goTracker.Go(func() { b.pollRequestEngineStatus(ctx) })
	}

	sender := &rateLimitingBusSender{fn: fn}
	defer sender.close()

	if mask&ipn.NotifyRateLimit != 0 {
		sender.interval = 3 * time.Second
	}

	sender.Run(ctx, ch)
}

// pollRequestEngineStatus calls b.e.RequestStatus every 2 seconds until ctx
// is done.
func (b *LocalBackend) pollRequestEngineStatus(ctx context.Context) {
	ticker, tickerChannel := b.clock.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-tickerChannel:
			b.e.RequestStatus()
		case <-ctx.Done():
			return
		}
	}
}

// DebugNotify injects a fake notify message to clients.
//
// It should only be used via the LocalAPI's debug handler.
func (b *LocalBackend) DebugNotify(n ipn.Notify) {
	b.send(n)
}

// DebugNotifyLastNetMap injects a fake notify message to clients,
// repeating whatever the last netmap was.
//
// It should only be used via the LocalAPI's debug handler.
func (b *LocalBackend) DebugNotifyLastNetMap() {
	b.mu.Lock()
	nm := b.netMap
	b.mu.Unlock()

	if nm != nil {
		b.send(ipn.Notify{NetMap: nm})
	}
}

// DebugForceNetmapUpdate forces a full no-op netmap update of the current
// netmap in all the various subsystems (wireguard, magicsock, LocalBackend).
//
// It exists for load testing reasons (for issue 1909), doing what would happen
// if a new MapResponse came in from the control server that couldn't be handled
// incrementally.
func (b *LocalBackend) DebugForceNetmapUpdate() {
	b.mu.Lock()
	defer b.mu.Unlock()
	nm := b.netMap
	b.e.SetNetworkMap(nm)
	if nm != nil {
		b.MagicConn().SetDERPMap(nm.DERPMap)
	}
	b.setNetMapLocked(nm)
}

// DebugPickNewDERP forwards to magicsock.Conn.DebugPickNewDERP.
// See its docs.
func (b *LocalBackend) DebugPickNewDERP() error {
	return b.sys.MagicSock.Get().DebugPickNewDERP()
}

// DebugForcePreferDERP forwards to netcheck.DebugForcePreferDERP.
// See its docs.
func (b *LocalBackend) DebugForcePreferDERP(n int) {
	b.sys.MagicSock.Get().DebugForcePreferDERP(n)
}

// send delivers n to the connected frontend and any API watchers from
// LocalBackend.WatchNotifications (via the LocalAPI).
//
// If no frontend is connected or API watchers are backed up, the notification
// is dropped without being delivered.
//
// If n contains Prefs, those will be sanitized before being delivered.
//
// b.mu must not be held.
func (b *LocalBackend) send(n ipn.Notify) {
	b.sendTo(n, allClients)
}

// notificationTarget describes a notification recipient.
// A zero value is valid and indicate that the notification
// should be broadcast to all active [watchSession]s.
type notificationTarget struct {
	// userID is the OS-specific UID of the target user.
	// If empty, the notification is not user-specific and
	// will be broadcast to all connected users.
	// TODO(nickkhyl): make this field cross-platform rather
	// than Windows-specific.
	userID ipn.WindowsUserID
	// clientID identifies a client that should be the exclusive recipient
	// of the notification. A zero value indicates that notification should
	// be sent to all sessions of the specified user.
	clientID ipnauth.ClientID
}

var allClients = notificationTarget{} // broadcast to all connected clients

// toNotificationTarget returns a [notificationTarget] that matches only actors
// representing the same user as the specified actor. If the actor represents
// a specific connected client, the [ipnauth.ClientID] must also match.
// If the actor is nil, the [notificationTarget] matches all actors.
func toNotificationTarget(actor ipnauth.Actor) notificationTarget {
	t := notificationTarget{}
	if actor != nil {
		t.userID = actor.UserID()
		t.clientID, _ = actor.ClientID()
	}
	return t
}

// match reports whether the specified actor should receive notifications
// targeting t. If the actor is nil, it should only receive notifications
// intended for all users.
func (t notificationTarget) match(actor ipnauth.Actor) bool {
	if t == allClients {
		return true
	}
	if actor == nil {
		return false
	}
	if t.userID != "" && t.userID != actor.UserID() {
		return false
	}
	if t.clientID != ipnauth.NoClientID {
		clientID, ok := actor.ClientID()
		if !ok || clientID != t.clientID {
			return false
		}
	}
	return true
}

// sendTo is like [LocalBackend.send] but allows specifying a recipient.
func (b *LocalBackend) sendTo(n ipn.Notify, recipient notificationTarget) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sendToLocked(n, recipient)
}

// sendToLocked is like [LocalBackend.sendTo], but assumes b.mu is already held.
func (b *LocalBackend) sendToLocked(n ipn.Notify, recipient notificationTarget) {
	if n.Prefs != nil {
		n.Prefs = ptr.To(stripKeysFromPrefs(*n.Prefs))
	}
	if n.Version == "" {
		n.Version = version.Long()
	}

	for _, sess := range b.notifyWatchers {
		if recipient.match(sess.owner) {
			select {
			case sess.ch <- &n:
			default:
				// Drop the notification if the channel is full.
			}
		}
	}
}

// setAuthURL sets the authURL and triggers [LocalBackend.popBrowserAuthNow] if the URL has changed.
// This method is called when a new authURL is received from the control plane, meaning that either a user
// has started a new interactive login (e.g., by running `tailscale login` or clicking Login in the GUI),
// or the control plane was unable to authenticate this node non-interactively (e.g., due to key expiration).
// A non-nil b.authActor indicates that an interactive login is in progress and was initiated by the specified actor.
// If url is "", it is equivalent to calling [LocalBackend.resetAuthURLLocked] with b.mu held.
func (b *LocalBackend) setAuthURL(url string) {
	var popBrowser, keyExpired bool
	var recipient ipnauth.Actor

	b.mu.Lock()
	switch {
	case url == "":
		b.resetAuthURLLocked()
		b.mu.Unlock()
		return
	case b.authURL != url:
		b.authURL = url
		b.authURLTime = b.clock.Now()
		// Always open the browser if the URL has changed.
		// This includes the transition from no URL -> some URL.
		popBrowser = true
	default:
		// Otherwise, only open it if the user explicitly requests interactive login.
		popBrowser = b.authActor != nil
	}
	keyExpired = b.keyExpired
	recipient = b.authActor // or nil
	// Consume the StartLoginInteractive call, if any, that caused the control
	// plane to send us this URL.
	b.authActor = nil
	b.mu.Unlock()

	if popBrowser {
		b.popBrowserAuthNow(url, keyExpired, recipient)
	}
}

// popBrowserAuthNow shuts down the data plane and sends the URL to the recipient's
// [watchSession]s if the recipient is non-nil; otherwise, it sends the URL to all watchSessions.
// keyExpired is the value of b.keyExpired upon entry and indicates
// whether the node's key has expired.
// It must not be called with b.mu held.
func (b *LocalBackend) popBrowserAuthNow(url string, keyExpired bool, recipient ipnauth.Actor) {
	b.logf("popBrowserAuthNow(%q): url=%v, key-expired=%v, seamless-key-renewal=%v", maybeUsernameOf(recipient), url != "", keyExpired, b.seamlessRenewalEnabled())

	// Deconfigure the local network data plane if:
	// - seamless key renewal is not enabled;
	// - key is expired (in which case tailnet connectivity is down anyway).
	if !b.seamlessRenewalEnabled() || keyExpired {
		b.blockEngineUpdates(true)
		b.stopEngineAndWait()
	}
	b.tellRecipientToBrowseToURL(url, toNotificationTarget(recipient))
	if b.State() == ipn.Running {
		b.enterState(ipn.Starting)
	}
}

// validPopBrowserURL reports whether urlStr is a valid value for a
// control server to send in a *URL field.
//
// b.mu must *not* be held.
func (b *LocalBackend) validPopBrowserURL(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	serverURL := b.Prefs().ControlURLOrDefault()
	if ipn.IsLoginServerSynonym(serverURL) {
		// When connected to the official Tailscale control plane, only allow
		// URLs from tailscale.com or its subdomains.
		if h := u.Hostname(); h != "tailscale.com" && !strings.HasSuffix(u.Hostname(), ".tailscale.com") {
			return false
		}
		// When using a different ControlURL, we cannot be sure what legitimate
		// PopBrowserURLs they will send. Allow any domain there to avoid
		// breaking existing user setups.
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		// If the control server is using plain HTTP (likely a dev server),
		// then permit http://.
		return strings.HasPrefix(serverURL, "http://")
	}
	return false
}

func (b *LocalBackend) tellClientToBrowseToURL(url string) {
	b.tellRecipientToBrowseToURL(url, allClients)
}

// tellRecipientToBrowseToURL is like tellClientToBrowseToURL but allows specifying a recipient.
func (b *LocalBackend) tellRecipientToBrowseToURL(url string, recipient notificationTarget) {
	if b.validPopBrowserURL(url) {
		b.sendTo(ipn.Notify{BrowseToURL: &url}, recipient)
	}
}

// onClientVersion is called on MapResponse updates when a MapResponse contains
// a non-nil ClientVersion message.
func (b *LocalBackend) onClientVersion(v *tailcfg.ClientVersion) {
	b.mu.Lock()
	b.lastClientVersion = v
	b.health.SetLatestVersion(v)
	b.mu.Unlock()
	b.send(ipn.Notify{ClientVersion: v})
}

func (b *LocalBackend) onTailnetDefaultAutoUpdate(au bool) {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	prefs := b.pm.CurrentPrefs()
	if !prefs.Valid() {
		b.logf("[unexpected]: received tailnet default auto-update callback but current prefs are nil")
		return
	}
	if _, ok := prefs.AutoUpdate().Apply.Get(); ok {
		// Apply was already set from a previous default or manually by the
		// user. Tailnet default should not affect us, even if it changes.
		return
	}
	if au && b.hostinfo != nil && b.hostinfo.Container.EqualBool(true) {
		// This is a containerized node, which is usually meant to be
		// immutable. Do not enable auto-updates if the tailnet does. But users
		// can still manually enable auto-updates on this node.
		return
	}
	b.logf("using tailnet default auto-update setting: %v", au)
	prefsClone := prefs.AsStruct()
	prefsClone.AutoUpdate.Apply = opt.NewBool(au)
	_, err := b.editPrefsLockedOnEntry(&ipn.MaskedPrefs{
		Prefs: *prefsClone,
		AutoUpdateSet: ipn.AutoUpdatePrefsMask{
			ApplySet: true,
		},
	}, unlock)
	if err != nil {
		b.logf("failed to apply tailnet-wide default for auto-updates (%v): %v", au, err)
		return
	}
}

// For testing lazy machine key generation.
var panicOnMachineKeyGeneration = envknob.RegisterBool("TS_DEBUG_PANIC_MACHINE_KEY")

func (b *LocalBackend) createGetMachinePrivateKeyFunc() func() (key.MachinePrivate, error) {
	var cache syncs.AtomicValue[key.MachinePrivate]
	return func() (key.MachinePrivate, error) {
		if panicOnMachineKeyGeneration() {
			panic("machine key generated")
		}
		if v, ok := cache.LoadOk(); ok {
			return v, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if v, ok := cache.LoadOk(); ok {
			return v, nil
		}
		if err := b.initMachineKeyLocked(); err != nil {
			return key.MachinePrivate{}, err
		}
		cache.Store(b.machinePrivKey)
		return b.machinePrivKey, nil
	}
}

// initMachineKeyLocked is called to initialize b.machinePrivKey.
//
// b.prefs must already be initialized.
// b.stateKey should be set too, but just for nicer log messages.
// b.mu must be held.
func (b *LocalBackend) initMachineKeyLocked() (err error) {
	if !b.machinePrivKey.IsZero() {
		// Already set.
		return nil
	}

	var legacyMachineKey key.MachinePrivate
	if p := b.pm.CurrentPrefs().Persist(); p.Valid() {
		legacyMachineKey = p.LegacyFrontendPrivateMachineKey()
	}

	keyText, err := b.store.ReadState(ipn.MachineKeyStateKey)
	if err == nil {
		if err := b.machinePrivKey.UnmarshalText(keyText); err != nil {
			return fmt.Errorf("invalid key in %s key of %v: %w", ipn.MachineKeyStateKey, b.store, err)
		}
		if b.machinePrivKey.IsZero() {
			return fmt.Errorf("invalid zero key stored in %v key of %v", ipn.MachineKeyStateKey, b.store)
		}
		if !legacyMachineKey.IsZero() && !legacyMachineKey.Equal(b.machinePrivKey) {
			b.logf("frontend-provided legacy machine key ignored; used value from server state")
		}
		return nil
	}
	if err != ipn.ErrStateNotExist {
		return fmt.Errorf("error reading %v key of %v: %w", ipn.MachineKeyStateKey, b.store, err)
	}

	// If we didn't find one already on disk and the prefs already
	// have a legacy machine key, use that. Otherwise generate a
	// new one.
	if !legacyMachineKey.IsZero() {
		b.machinePrivKey = legacyMachineKey
	} else {
		b.logf("generating new machine key")
		b.machinePrivKey = key.NewMachine()
	}

	keyText, _ = b.machinePrivKey.MarshalText()
	if err := ipn.WriteState(b.store, ipn.MachineKeyStateKey, keyText); err != nil {
		b.logf("error writing machine key to store: %v", err)
		return err
	}

	b.logf("machine key written to store")
	return nil
}

// clearMachineKeyLocked is called to clear the persisted and in-memory
// machine key, so that initMachineKeyLocked (called as part of starting)
// generates a new machine key.
//
// b.mu must be held.
func (b *LocalBackend) clearMachineKeyLocked() error {
	if err := ipn.WriteState(b.store, ipn.MachineKeyStateKey, nil); err != nil {
		return err
	}
	b.machinePrivKey = key.MachinePrivate{}
	b.logf("machine key cleared")
	return nil
}

// setTCPPortsIntercepted populates b.shouldInterceptTCPPortAtomic with an
// efficient func for ShouldInterceptTCPPort to use, which is called on every
// incoming packet.
func (b *LocalBackend) setTCPPortsIntercepted(ports []uint16) {
	slices.Sort(ports)
	uniq.ModifySlice(&ports)
	var f func(uint16) bool
	switch len(ports) {
	case 0:
		f = func(uint16) bool { return false }
	case 1:
		f = func(p uint16) bool { return ports[0] == p }
	case 2:
		f = func(p uint16) bool { return ports[0] == p || ports[1] == p }
	case 3:
		f = func(p uint16) bool { return ports[0] == p || ports[1] == p || ports[2] == p }
	default:
		if len(ports) > 16 {
			m := map[uint16]bool{}
			for _, p := range ports {
				m[p] = true
			}
			f = func(p uint16) bool { return m[p] }
		} else {
			f = func(p uint16) bool {
				for _, x := range ports {
					if p == x {
						return true
					}
				}
				return false
			}
		}
	}
	b.shouldInterceptTCPPortAtomic.Store(f)
}

// setAtomicValuesFromPrefsLocked populates sshAtomicBool, containsViaIPFuncAtomic,
// shouldInterceptTCPPortAtomic, and exposeRemoteWebClientAtomicBool from the prefs p,
// which may be !Valid().
func (b *LocalBackend) setAtomicValuesFromPrefsLocked(p ipn.PrefsView) {
	b.sshAtomicBool.Store(p.Valid() && p.RunSSH() && envknob.CanSSHD())

	if !p.Valid() {
		b.containsViaIPFuncAtomic.Store(ipset.FalseContainsIPFunc())
		b.setTCPPortsIntercepted(nil)
	} else {
		filtered := tsaddr.FilterPrefixesCopy(p.AdvertiseRoutes(), tsaddr.IsViaPrefix)
		b.containsViaIPFuncAtomic.Store(ipset.NewContainsIPFunc(views.SliceOf(filtered)))
	}
}

// State returns the backend state machine's current state.
func (b *LocalBackend) State() ipn.State {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.state
}

// InServerMode reports whether the Tailscale backend is explicitly running in
// "server mode" where it continues to run despite whatever the platform's
// default is. In practice, this is only used on Windows, where the default
// tailscaled behavior is to shut down whenever the GUI disconnects.
//
// On non-Windows platforms, this usually returns false (because people don't
// set unattended mode on other platforms) and also isn't checked on other
// platforms.
//
// TODO(bradfitz): rename to InWindowsUnattendedMode or something? Or make this
// return true on Linux etc and always be called? It's kinda messy now.
func (b *LocalBackend) InServerMode() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.CurrentPrefs().ForceDaemon()
}

// CheckIPNConnectionAllowed returns an error if the specified actor should not
// be allowed to connect or make requests to the LocalAPI currently.
//
// Currently (as of 2024-08-26), this is only used on Windows.
// We plan to remove it as part of the multi-user and unattended mode improvements
// as we progress on tailscale/corp#18342.
func (b *LocalBackend) CheckIPNConnectionAllowed(actor ipnauth.Actor) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	serverModeUid := b.pm.CurrentUserID()
	if serverModeUid == "" {
		// Either this platform isn't a "multi-user" platform or we're not yet
		// running as one.
		return nil
	}
	if !b.pm.CurrentPrefs().ForceDaemon() {
		return nil
	}

	// Always allow Windows SYSTEM user to connect,
	// even if Tailscale is currently being used by another user.
	if actor.IsLocalSystem() {
		return nil
	}

	uid := actor.UserID()
	if uid == "" {
		return errors.New("empty user uid in connection identity")
	}
	if uid != serverModeUid {
		return fmt.Errorf("Tailscale running in server mode (%q); connection from %q not allowed", b.tryLookupUserName(string(serverModeUid)), b.tryLookupUserName(string(uid)))
	}
	return nil
}

// tryLookupUserName tries to look up the username for the uid.
// It returns the username on success, or the UID on failure.
func (b *LocalBackend) tryLookupUserName(uid string) string {
	u, err := ipnauth.LookupUserFromID(b.logf, uid)
	if err != nil {
		return uid
	}
	return u.Username
}

// StartLoginInteractive requests a new interactive login from controlclient,
// unless such a flow is already in progress, in which case
// StartLoginInteractive attempts to pick up the in-progress flow where it left
// off.
func (b *LocalBackend) StartLoginInteractive(ctx context.Context) error {
	return b.StartLoginInteractiveAs(ctx, nil)
}

// StartLoginInteractiveAs is like StartLoginInteractive but takes an [ipnauth.Actor]
// as an additional parameter. If non-nil, the specified user is expected to complete
// the interactive login, and therefore will receive the BrowseToURL notification once
// the control plane sends us one. Otherwise, the notification will be delivered to all
// active [watchSession]s.
func (b *LocalBackend) StartLoginInteractiveAs(ctx context.Context, user ipnauth.Actor) error {
	b.mu.Lock()
	if b.cc == nil {
		panic("LocalBackend.assertClient: b.cc == nil")
	}
	url := b.authURL
	keyExpired := b.keyExpired
	timeSinceAuthURLCreated := b.clock.Since(b.authURLTime)
	// Only use an authURL if it was sent down from control in the last
	// 6 days and 23 hours. Avoids using a stale URL that is no longer valid
	// server-side. Server-side URLs expire after 7 days.
	hasValidURL := url != "" && timeSinceAuthURLCreated < ((7*24*time.Hour)-(1*time.Hour))
	if !hasValidURL {
		// A user wants to log in interactively, but we don't have a valid authURL.
		// Remember the user who initiated the login, so that we can notify them
		// once the authURL is available.
		b.authActor = user
	}
	cc := b.cc
	b.mu.Unlock()

	b.logf("StartLoginInteractiveAs(%q): url=%v", maybeUsernameOf(user), hasValidURL)

	if hasValidURL {
		b.popBrowserAuthNow(url, keyExpired, user)
	} else {
		cc.Login(b.loginFlags | controlclient.LoginInteractive)
	}
	return nil
}

func (b *LocalBackend) Ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType, size int) (*ipnstate.PingResult, error) {
	if pingType == tailcfg.PingPeerAPI {
		t0 := b.clock.Now()
		node, base, err := b.pingPeerAPI(ctx, ip)
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		d := b.clock.Since(t0)
		pr := &ipnstate.PingResult{
			IP:             ip.String(),
			NodeIP:         ip.String(),
			LatencySeconds: d.Seconds(),
			PeerAPIURL:     base,
		}
		if err != nil {
			pr.Err = err.Error()
		}
		if node.Valid() {
			pr.NodeName = node.Name()
		}
		return pr, nil
	}
	ch := make(chan *ipnstate.PingResult, 1)
	b.e.Ping(ip, pingType, size, func(pr *ipnstate.PingResult) {
		select {
		case ch <- pr:
		default:
		}
	})
	select {
	case pr := <-ch:
		return pr, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *LocalBackend) pingPeerAPI(ctx context.Context, ip netip.Addr) (peer tailcfg.NodeView, peerBase string, err error) {
	var zero tailcfg.NodeView
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nm := b.NetMap()
	if nm == nil {
		return zero, "", errors.New("no netmap")
	}
	peer, ok := nm.PeerByTailscaleIP(ip)
	if !ok {
		return zero, "", fmt.Errorf("no peer found with Tailscale IP %v", ip)
	}
	if peer.Expired() {
		return zero, "", errors.New("peer's node key has expired")
	}
	base := peerAPIBase(nm, peer)
	if base == "" {
		return zero, "", fmt.Errorf("no PeerAPI base found for peer %v (%v)", peer.ID(), ip)
	}
	outReq, err := http.NewRequestWithContext(ctx, "HEAD", base, nil)
	if err != nil {
		return zero, "", err
	}
	tr := b.Dialer().PeerAPITransport()
	res, err := tr.RoundTrip(outReq)
	if err != nil {
		return zero, "", err
	}
	defer res.Body.Close() // but unnecessary on HEAD responses
	if res.StatusCode != http.StatusOK {
		return zero, "", fmt.Errorf("HTTP status %v", res.Status)
	}
	return peer, base, nil
}

// parseWgStatusLocked returns an EngineStatus based on s.
//
// b.mu must be held; mostly because the caller is about to anyway, and doing so
// gives us slightly better guarantees about the two peers stats lines not
// being intermixed if there are concurrent calls to our caller.
func (b *LocalBackend) parseWgStatusLocked(s *wgengine.Status) (ret ipn.EngineStatus) {
	var peerStats, peerKeys strings.Builder

	ret.LiveDERPs = s.DERPs
	ret.LivePeers = map[key.NodePublic]ipnstate.PeerStatusLite{}
	for _, p := range s.Peers {
		if !p.LastHandshake.IsZero() {
			fmt.Fprintf(&peerStats, "%d/%d ", p.RxBytes, p.TxBytes)
			fmt.Fprintf(&peerKeys, "%s ", p.NodeKey.ShortString())

			ret.NumLive++
			ret.LivePeers[p.NodeKey] = p

		}
		ret.RBytes += p.RxBytes
		ret.WBytes += p.TxBytes
	}

	// [GRINDER STATS LINES] - please don't remove (used for log parsing)
	if peerStats.Len() > 0 {
		b.keyLogf("[v1] peer keys: %s", strings.TrimSpace(peerKeys.String()))
		b.statsLogf("[v1] v%v peers: %v", version.Long(), strings.TrimSpace(peerStats.String()))
	}
	return ret
}

// shouldUploadServices reports whether this node should include services
// in Hostinfo. When the user preferences currently request "shields up"
// mode, all inbound connections are refused, so services are not reported.
// Otherwise, shouldUploadServices respects NetMap.CollectServices.
func (b *LocalBackend) shouldUploadServices() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	p := b.pm.CurrentPrefs()
	if !p.Valid() || b.netMap == nil {
		return false // default to safest setting
	}
	return !p.ShieldsUp() && b.netMap.CollectServices
}

// SetCurrentUser is used to implement support for multi-user systems (only
// Windows 2022-11-25). On such systems, the uid is used to determine which
// user's state should be used. The current user is maintained by active
// connections open to the backend.
//
// When the backend initially starts it will typically start with no user. Then,
// the first connection to the backend from the GUI frontend will set the
// current user. Once set, the current user cannot be changed until all previous
// connections are closed. The user is also used to determine which
// LoginProfiles are accessible.
//
// In unattended mode, the backend will start with the user which enabled
// unattended mode. The user must disable unattended mode before the user can be
// changed.
//
// On non-multi-user systems, the user should be set to nil.
//
// SetCurrentUser returns the ipn.WindowsUserID associated with the user
// when successful.
func (b *LocalBackend) SetCurrentUser(actor ipnauth.Actor) (ipn.WindowsUserID, error) {
	var uid ipn.WindowsUserID
	if actor != nil {
		uid = actor.UserID()
	}

	unlock := b.lockAndGetUnlock()
	defer unlock()

	if b.pm.CurrentUserID() == uid {
		return uid, nil
	}
	b.pm.SetCurrentUserID(uid)
	if c, ok := b.currentUser.(ipnauth.ActorCloser); ok {
		c.Close()
	}
	b.currentUser = actor
	b.resetForProfileChangeLockedOnEntry(unlock)
	return uid, nil
}

func (b *LocalBackend) CheckPrefs(p *ipn.Prefs) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checkPrefsLocked(p)
}

// isConfigLocked_Locked reports whether the parsed config file is locked.
// b.mu must be held.
func (b *LocalBackend) isConfigLocked_Locked() bool {
	// TODO(bradfitz,maisem): make this more fine-grained, permit changing
	// some things if they're not explicitly set in the config. But for now
	// (2023-10-16), just blanket disable everything.
	return b.conf != nil && !b.conf.Parsed.Locked.EqualBool(false)
}

func (b *LocalBackend) checkPrefsLocked(p *ipn.Prefs) error {
	if b.isConfigLocked_Locked() {
		return errors.New("can't reconfigure tailscaled when using a config file; config file is locked")
	}
	var errs []error
	if p.Hostname == "badhostname.tailscale." {
		// Keep this one just for testing.
		errs = append(errs, errors.New("bad hostname [test]"))
	}
	if err := b.checkProfileNameLocked(p); err != nil {
		errs = append(errs, err)
	}
	if err := b.checkSSHPrefsLocked(p); err != nil {
		errs = append(errs, err)
	}
	if err := b.checkExitNodePrefsLocked(p); err != nil {
		errs = append(errs, err)
	}
	if err := b.checkAutoUpdatePrefsLocked(p); err != nil {
		errs = append(errs, err)
	}
	return multierr.New(errs...)
}

func (b *LocalBackend) checkSSHPrefsLocked(p *ipn.Prefs) error {
	if !p.RunSSH {
		return nil
	}
	if err := featureknob.CanRunTailscaleSSH(); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		b.updateSELinuxHealthWarning()
	}
	if envknob.SSHIgnoreTailnetPolicy() || envknob.SSHPolicyFile() != "" {
		return nil
	}
	if b.netMap != nil {
		if !b.netMap.HasCap(tailcfg.CapabilitySSH) {
			if b.isDefaultServerLocked() {
				return errors.New("Unable to enable local Tailscale SSH server; not enabled on Tailnet. See https://tailscale.com/s/ssh")
			}
			return errors.New("Unable to enable local Tailscale SSH server; not enabled on Tailnet.")
		}
	}
	return nil
}

func (b *LocalBackend) sshOnButUnusableHealthCheckMessageLocked() (healthMessage string) {
	if p := b.pm.CurrentPrefs(); !p.Valid() || !p.RunSSH() {
		return ""
	}
	if envknob.SSHIgnoreTailnetPolicy() || envknob.SSHPolicyFile() != "" {
		return "development SSH policy in use"
	}
	nm := b.netMap
	if nm == nil {
		return ""
	}
	if nm.SSHPolicy != nil && len(nm.SSHPolicy.Rules) > 0 {
		return ""
	}
	isDefault := b.isDefaultServerLocked()

	if !nm.HasCap(tailcfg.CapabilityAdmin) {
		return healthmsg.TailscaleSSHOnBut + "access controls don't allow anyone to access this device. Ask your admin to update your tailnet's ACLs to allow access."
	}
	if !isDefault {
		return healthmsg.TailscaleSSHOnBut + "access controls don't allow anyone to access this device. Update your tailnet's ACLs to allow access."
	}
	return healthmsg.TailscaleSSHOnBut + "access controls don't allow anyone to access this device. Update your tailnet's ACLs at https://tailscale.com/s/ssh-policy"
}

func (b *LocalBackend) isDefaultServerLocked() bool {
	prefs := b.pm.CurrentPrefs()
	if !prefs.Valid() {
		return true // assume true until set otherwise
	}
	return prefs.ControlURLOrDefault() == ipn.DefaultControlURL
}

var exitNodeMisconfigurationWarnable = health.Register(&health.Warnable{
	Code:     "exit-node-misconfiguration",
	Title:    "Exit node misconfiguration",
	Severity: health.SeverityMedium,
	Text: func(args health.Args) string {
		return "Exit node misconfiguration: " + args[health.ArgError]
	},
})

// updateExitNodeUsageWarning updates a warnable meant to notify users of
// configuration issues that could break exit node usage.
func updateExitNodeUsageWarning(p ipn.PrefsView, state *netmon.State, healthTracker *health.Tracker) {
	var msg string
	if p.ExitNodeIP().IsValid() || p.ExitNodeID() != "" {
		warn, _ := netutil.CheckReversePathFiltering(state)
		const comment = "please set rp_filter=2 instead of rp_filter=1; see https://github.com/tailscale/tailscale/issues/3310"
		if len(warn) > 0 {
			msg = fmt.Sprintf("%s: %v, %s", healthmsg.WarnExitNodeUsage, warn, comment)
		}
	}
	if len(msg) > 0 {
		healthTracker.SetUnhealthy(exitNodeMisconfigurationWarnable, health.Args{health.ArgError: msg})
	} else {
		healthTracker.SetHealthy(exitNodeMisconfigurationWarnable)
	}
}

func (b *LocalBackend) checkExitNodePrefsLocked(p *ipn.Prefs) error {
	tryingToUseExitNode := p.ExitNodeIP.IsValid() || p.ExitNodeID != ""
	if !tryingToUseExitNode {
		return nil
	}

	if err := featureknob.CanUseExitNode(); err != nil {
		return err
	}

	if p.AdvertisesExitNode() {
		return errors.New("Cannot advertise an exit node and use an exit node at the same time.")
	}
	return nil
}

func (b *LocalBackend) checkAutoUpdatePrefsLocked(p *ipn.Prefs) error {
	return nil
}

// SetUseExitNodeEnabled turns on or off the most recently selected exit node.
//
// On success, it returns the resulting prefs (or current prefs, in the case of no change).
// Setting the value to false when use of an exit node is already false is not an error,
// nor is true when the exit node is already in use.
func (b *LocalBackend) SetUseExitNodeEnabled(v bool) (ipn.PrefsView, error) {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	p0 := b.pm.CurrentPrefs()
	if v && p0.ExitNodeID() != "" {
		// Already on.
		return p0, nil
	}
	if !v && p0.ExitNodeID() == "" {
		// Already off.
		return p0, nil
	}

	var zero ipn.PrefsView
	if v && p0.InternalExitNodePrior() == "" {
		if !p0.ExitNodeIP().IsValid() {
			return zero, errors.New("no exit node IP to enable & prior exit node IP was never resolved an a node")
		}
		return zero, errors.New("no prior exit node to enable")
	}

	mp := &ipn.MaskedPrefs{}
	if v {
		mp.ExitNodeIDSet = true
		mp.ExitNodeID = tailcfg.StableNodeID(p0.InternalExitNodePrior())
	} else {
		mp.ExitNodeIDSet = true
		mp.ExitNodeID = ""
		mp.InternalExitNodePriorSet = true
		mp.InternalExitNodePrior = p0.ExitNodeID()
	}
	return b.editPrefsLockedOnEntry(mp, unlock)
}

func (b *LocalBackend) EditPrefs(mp *ipn.MaskedPrefs) (ipn.PrefsView, error) {
	if mp.SetsInternal() {
		return ipn.PrefsView{}, errors.New("can't set Internal fields")
	}

	// Zeroing the ExitNodeId via localAPI must also zero the prior exit node.
	if mp.ExitNodeIDSet && mp.ExitNodeID == "" {
		mp.InternalExitNodePrior = ""
		mp.InternalExitNodePriorSet = true
	}

	unlock := b.lockAndGetUnlock()
	defer unlock()
	return b.editPrefsLockedOnEntry(mp, unlock)
}

// Warning: b.mu must be held on entry, but it unlocks it on the way out.
// TODO(bradfitz): redo the locking on all these weird methods like this.
func (b *LocalBackend) editPrefsLockedOnEntry(mp *ipn.MaskedPrefs, unlock unlockOnce) (ipn.PrefsView, error) {
	defer unlock() // for error paths

	if mp.EggSet {
		mp.EggSet = false
		b.egg = true
		b.goTracker.Go(b.doSetHostinfoFilterServices)
	}
	p0 := b.pm.CurrentPrefs()
	p1 := b.pm.CurrentPrefs().AsStruct()
	p1.ApplyEdits(mp)
	if err := b.checkPrefsLocked(p1); err != nil {
		b.logf("EditPrefs check error: %v", err)
		return ipn.PrefsView{}, err
	}
	if p1.RunSSH && !envknob.CanSSHD() {
		b.logf("EditPrefs requests SSH, but disabled by envknob; returning error")
		return ipn.PrefsView{}, errors.New("Tailscale SSH server administratively disabled.")
	}
	if p1.View().Equals(p0) {
		return stripKeysFromPrefs(p0), nil
	}
	b.logf("EditPrefs: %v", mp.Pretty())
	newPrefs := b.setPrefsLockedOnEntry(p1, unlock)

	// Note: don't perform any actions for the new prefs here. Not
	// every prefs change goes through EditPrefs. Put your actions
	// in setPrefsLocksOnEntry instead.

	// This should return the public prefs, not the private ones.
	return stripKeysFromPrefs(newPrefs), nil
}

func (b *LocalBackend) checkProfileNameLocked(p *ipn.Prefs) error {
	if p.ProfileName == "" {
		// It is always okay to clear the profile name.
		return nil
	}
	id := b.pm.ProfileIDForName(p.ProfileName)
	if id == "" {
		// No profile with that name exists. That's fine.
		return nil
	}
	if id != b.pm.CurrentProfile().ID {
		// Name is already in use by another profile.
		return fmt.Errorf("profile name %q already in use", p.ProfileName)
	}
	return nil
}

// setPrefsLockedOnEntry requires b.mu be held to call it, but it
// unlocks b.mu when done. newp ownership passes to this function.
// It returns a readonly copy of the new prefs.
func (b *LocalBackend) setPrefsLockedOnEntry(newp *ipn.Prefs, unlock unlockOnce) ipn.PrefsView {
	defer unlock()

	netMap := b.netMap
	b.setAtomicValuesFromPrefsLocked(newp.View())

	oldp := b.pm.CurrentPrefs()
	if oldp.Valid() {
		newp.Persist = oldp.Persist().AsStruct() // caller isn't allowed to override this
	}
	// applySysPolicyToPrefsLocked returns whether it updated newp,
	// but everything in this function treats b.prefs as completely new
	// anyway, so its return value can be ignored here.
	applySysPolicy(newp, b.lastSuggestedExitNode)
	// setExitNodeID does likewise. No-op if no exit node resolution is needed.
	setExitNodeID(newp, netMap)
	// We do this to avoid holding the lock while doing everything else.

	oldHi := b.hostinfo
	newHi := oldHi.Clone()
	if newHi == nil {
		newHi = new(tailcfg.Hostinfo)
	}
	b.applyPrefsToHostinfoLocked(newHi, newp.View())
	b.hostinfo = newHi
	hostInfoChanged := !oldHi.Equal(newHi)
	cc := b.cc

	b.updateFilterLocked(netMap, newp.View())

	if oldp.ShouldSSHBeRunning() && !newp.ShouldSSHBeRunning() {
		if b.sshServer != nil {
			b.goTracker.Go(b.sshServer.Shutdown)
			b.sshServer = nil
		}
	}
	if netMap != nil {
		newProfile := netMap.UserProfiles[netMap.User()]
		if newLoginName := newProfile.LoginName; newLoginName != "" {
			if !oldp.Persist().Valid() {
				b.logf("active login: %s", newLoginName)
			} else {
				oldLoginName := oldp.Persist().UserProfile().LoginName
				if oldLoginName != newLoginName {
					b.logf("active login: %q (changed from %q)", newLoginName, oldLoginName)
				}
				newp.Persist.UserProfile = newProfile
			}
		}
	}

	prefs := newp.View()
	np := b.pm.CurrentProfile().NetworkProfile
	if netMap != nil {
		np = ipn.NetworkProfile{
			MagicDNSName: b.netMap.MagicDNSSuffix(),
			DomainName:   b.netMap.DomainName(),
		}
	}
	if err := b.pm.SetPrefs(prefs, np); err != nil {
		b.logf("failed to save new controlclient state: %v", err)
	}

	unlock.UnlockEarly()

	if oldp.ShieldsUp() != newp.ShieldsUp || hostInfoChanged {
		b.doSetHostinfoFilterServices()
	}

	if netMap != nil {
		b.MagicConn().SetDERPMap(netMap.DERPMap)
	}

	if !oldp.WantRunning() && newp.WantRunning {
		b.logf("transitioning to running; doing Login...")
		cc.Login(controlclient.LoginDefault)
	}

	if oldp.WantRunning() != newp.WantRunning {
		b.stateMachine()
	} else {
		b.authReconfig()
	}

	b.send(ipn.Notify{Prefs: &prefs})
	return prefs
}

func (b *LocalBackend) isLocalIP(ip netip.Addr) bool {
	nm := b.NetMap()
	return nm != nil && views.SliceContains(nm.GetAddresses(), netip.PrefixFrom(ip, ip.BitLen()))
}

var (
	magicDNSIP   = tsaddr.TailscaleServiceIP()
	magicDNSIPv6 = tsaddr.TailscaleServiceIPv6()
)

// doSetHostinfoFilterServices calls SetHostinfo on the controlclient,
// possibly after mangling the given hostinfo.
//
// TODO(danderson): we shouldn't be mangling hostinfo here after
// painstakingly constructing it in twelvety other places.
func (b *LocalBackend) doSetHostinfoFilterServices() {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	cc := b.cc
	if cc == nil {
		// Control client isn't up yet.
		return
	}
	if b.hostinfo == nil {
		b.logf("[unexpected] doSetHostinfoFilterServices with nil hostinfo")
		return
	}

	// TODO(maisem,bradfitz): store hostinfo as a view, not as a mutable struct.
	hi := *b.hostinfo // shallow copy
	unlock.UnlockEarly()

	// Make a shallow copy of hostinfo so we can mutate
	// at the Service field.
	if !b.shouldUploadServices() {
		hi.Services = []tailcfg.Service{}
	}
	// Don't mutate hi.Service's underlying array. Append to
	// the slice with no free capacity.
	hi.PushDeviceToken = b.pushDeviceToken.Load()
	cc.SetHostinfo(&hi)
}

// NetMap returns the latest cached network map received from
// controlclient, or nil if no network map was received yet.
func (b *LocalBackend) NetMap() *netmap.NetworkMap {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.netMap
}

func (b *LocalBackend) isEngineBlocked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocked
}

// blockEngineUpdate sets b.blocked to block, while holding b.mu. Its
// indirect effect is to turn b.authReconfig() into a no-op if block
// is true.
func (b *LocalBackend) blockEngineUpdates(block bool) {
	b.logf("blockEngineUpdates(%v)", block)

	b.mu.Lock()
	b.blocked = block
	b.mu.Unlock()
}

// authReconfig pushes a new configuration into wgengine, if engine
// updates are not currently blocked, based on the cached netmap and
// user prefs.
func (b *LocalBackend) authReconfig() {
	b.mu.Lock()
	blocked := b.blocked
	prefs := b.pm.CurrentPrefs()
	nm := b.netMap
	hasPAC := b.prevIfState.HasPAC()
	disableSubnetsIfPAC := nm.HasCap(tailcfg.NodeAttrDisableSubnetsIfPAC)
	userDialUseRoutes := nm.HasCap(tailcfg.NodeAttrUserDialUseRoutes)
	// If the current node is an app connector, ensure the app connector machine is started
	closing := b.shutdownCalled
	b.mu.Unlock()

	if closing {
		b.logf("[v1] authReconfig: skipping because in shutdown")
		return
	}

	if blocked {
		b.logf("[v1] authReconfig: blocked, skipping.")
		return
	}
	if nm == nil {
		b.logf("[v1] authReconfig: netmap not yet valid. Skipping.")
		return
	}
	if !prefs.WantRunning() {
		b.logf("[v1] authReconfig: skipping because !WantRunning.")
		return
	}

	var flags netmap.WGConfigFlags
	if prefs.RouteAll() {
		flags |= netmap.AllowSubnetRoutes
	}
	if hasPAC && disableSubnetsIfPAC {
		if flags&netmap.AllowSubnetRoutes != 0 {
			b.logf("authReconfig: have PAC; disabling subnet routes")
			flags &^= netmap.AllowSubnetRoutes
		}
	}

	cfg, err := nmcfg.WGCfg(nm, b.logf, flags, prefs.ExitNodeID())
	if err != nil {
		b.logf("wgcfg: %v", err)
		return
	}

	oneCGNATRoute := shouldUseOneCGNATRoute(b.logf, b.sys.ControlKnobs(), version.OS())
	rcfg := b.routerConfig(cfg, prefs, oneCGNATRoute)

	err = b.e.Reconfig(cfg, rcfg)
	if err == wgengine.ErrNoChanges {
		return
	}
	b.logf("[v1] authReconfig: ra=%v dns=%v 0x%02x: %v", prefs.RouteAll(), prefs.CorpDNS(), flags, err)

	if userDialUseRoutes {
		b.dialer.SetRoutes(rcfg.Routes, rcfg.LocalRoutes)
	} else {
		b.dialer.SetRoutes(nil, nil)
	}
}

// shouldUseOneCGNATRoute reports whether we should prefer to make one big
// CGNAT /10 route rather than a /32 per peer.
//
// The versionOS is a Tailscale-style version ("iOS", "macOS") and not
// a runtime.GOOS.
func shouldUseOneCGNATRoute(logf logger.Logf, controlKnobs *controlknobs.Knobs, versionOS string) bool {
	if controlKnobs != nil {
		// Explicit enabling or disabling always take precedence.
		if v, ok := controlKnobs.OneCGNAT.Load().Get(); ok {
			logf("[v1] shouldUseOneCGNATRoute: explicit=%v", v)
			return v
		}
	}

	// Also prefer to do this on the Mac, so that we don't need to constantly
	// update the network extension configuration (which is disruptive to
	// Chrome, see https://github.com/tailscale/tailscale/issues/3102). Only
	// use fine-grained routes if another interfaces is also using the CGNAT
	// IP range.
	if versionOS == "macOS" {
		hasCGNATInterface, err := netmon.HasCGNATInterface()
		if err != nil {
			logf("shouldUseOneCGNATRoute: Could not determine if any interfaces use CGNAT: %v", err)
			return false
		}
		logf("[v1] shouldUseOneCGNATRoute: macOS automatic=%v", !hasCGNATInterface)
		if !hasCGNATInterface {
			return true
		}
	}
	return false
}

// SetTCPHandlerForFunnelFlow sets the TCP handler for Funnel flows.
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetTCPHandlerForFunnelFlow(h func(src netip.AddrPort, dstPort uint16) (handler func(net.Conn))) {
	b.getTCPHandlerForFunnelFlow = h
}

// SetVarRoot sets the root directory of Tailscale's writable
// storage area . (e.g. "/var/lib/tailscale")
//
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetVarRoot(dir string) {
	b.varRoot = dir
}

// SetLogFlusher sets a func to be called to flush log uploads.
//
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetLogFlusher(flushFunc func()) {
	b.logFlushFunc = flushFunc
}

// TryFlushLogs calls the log flush function. It returns false if a log flush
// function was never initialized with SetLogFlusher.
//
// TryFlushLogs should not block.
func (b *LocalBackend) TryFlushLogs() bool {
	if b.logFlushFunc == nil {
		return false
	}
	b.logFlushFunc()
	return true
}

// TailscaleVarRoot returns the root directory of Tailscale's writable
// storage area. (e.g. "/var/lib/tailscale")
//
// It returns an empty string if there's no configured or discovered
// location.
func (b *LocalBackend) TailscaleVarRoot() string {
	if b.varRoot != "" {
		return b.varRoot
	}
	switch runtime.GOOS {
	case "ios", "android", "darwin":
		return paths.AppSharedDir.Load()
	case "linux":
		if distro.Get() == distro.Gokrazy {
			return "/perm/tailscaled"
		}
	}
	return ""
}

func (b *LocalBackend) fileRootLocked(uid tailcfg.UserID) string {
	if v := b.directFileRoot; v != "" {
		return v
	}
	varRoot := b.TailscaleVarRoot()
	if varRoot == "" {
		b.logf("Taildrop disabled; no state directory")
		return ""
	}
	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(b.activeLogin, "@", "-"),
		uid)
	dir := filepath.Join(varRoot, "files", baseDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		b.logf("Taildrop disabled; error making directory: %v", err)
		return ""
	}
	return dir
}

// peerAPIListenAsync is whether the operating system requires that we
// retry listening on the peerAPI ip/port for whatever reason.
//
// On Windows, see Issue 1620.
// On Android, see Issue 1960.
const peerAPIListenAsync = runtime.GOOS == "windows" || runtime.GOOS == "android"

// peerRoutes returns the routerConfig.Routes to access peers.
// If there are over cgnatThreshold CGNAT routes, one big CGNAT route
// is used instead.
func peerRoutes(logf logger.Logf, peers []wgcfg.Peer, cgnatThreshold int) (routes []netip.Prefix) {
	tsULA := tsaddr.TailscaleULARange()
	cgNAT := tsaddr.CGNATRange()
	var didULA bool
	var cgNATIPs []netip.Prefix
	for _, peer := range peers {
		for _, aip := range peer.AllowedIPs {
			aip = unmapIPPrefix(aip)

			// Ensure that we're only accepting properly-masked
			// prefixes; the control server should be masking
			// these, so if we get them, skip.
			if mm := aip.Masked(); aip != mm {
				// To avoid a DoS where a peer could cause all
				// reconfigs to fail by sending a bad prefix, we just
				// skip, but don't error, on an unmasked route.
				logf("advertised route %s from %s has non-address bits set; expected %s", aip, peer.PublicKey.ShortString(), mm)
				continue
			}

			// Only add the Tailscale IPv6 ULA once, if we see anybody using part of it.
			if aip.Addr().Is6() && aip.IsSingleIP() && tsULA.Contains(aip.Addr()) {
				if !didULA {
					didULA = true
					routes = append(routes, tsULA)
				}
				continue
			}
			if aip.IsSingleIP() && cgNAT.Contains(aip.Addr()) {
				cgNATIPs = append(cgNATIPs, aip)
			} else {
				routes = append(routes, aip)
			}
		}
	}
	if len(cgNATIPs) > cgnatThreshold {
		// Probably the hello server. Just append one big route.
		routes = append(routes, cgNAT)
	} else {
		routes = append(routes, cgNATIPs...)
	}

	tsaddr.SortPrefixes(routes)
	return routes
}

// routerConfig produces a router.Config from a wireguard config and IPN prefs.
func (b *LocalBackend) routerConfig(cfg *wgcfg.Config, prefs ipn.PrefsView, oneCGNATRoute bool) *router.Config {
	singleRouteThreshold := 10_000
	if oneCGNATRoute {
		singleRouteThreshold = 1
	}

	b.mu.Lock()
	netfilterKind := b.capForcedNetfilter // protected by b.mu
	b.mu.Unlock()

	if prefs.NetfilterKind() != "" {
		if netfilterKind != "" {
			b.logf("nodeattr netfilter preference %s overridden by c2n pref %s", netfilterKind, prefs.NetfilterKind())
		}
		netfilterKind = prefs.NetfilterKind()
	}

	var doStatefulFiltering bool
	if v, ok := prefs.NoStatefulFiltering().Get(); ok && !v {
		// The preferences explicitly "do stateful filtering" is turned
		// off, or to expand the double negative, to do stateful
		// filtering. Do so.
		doStatefulFiltering = true
	}

	rs := &router.Config{
		LocalAddrs:        unmapIPPrefixes(cfg.Addresses),
		SubnetRoutes:      unmapIPPrefixes(prefs.AdvertiseRoutes().AsSlice()),
		SNATSubnetRoutes:  !prefs.NoSNAT(),
		StatefulFiltering: doStatefulFiltering,
		NetfilterMode:     prefs.NetfilterMode(),
		Routes:            peerRoutes(b.logf, cfg.Peers, singleRouteThreshold),
		NetfilterKind:     netfilterKind,
	}

	if distro.Get() == distro.Synology {
		// Issue 1995: we don't use iptables on Synology.
		rs.NetfilterMode = preftype.NetfilterOff
	}

	// Sanity check: we expect the control server to program both a v4
	// and a v6 default route, if default routing is on. Fill in
	// blackhole routes appropriately if we're missing some. This is
	// likely to break some functionality, but if the user expressed a
	// preference for routing remotely, we want to avoid leaking
	// traffic at the expense of functionality.
	if prefs.ExitNodeID() != "" || prefs.ExitNodeIP().IsValid() {
		var default4, default6 bool
		for _, route := range rs.Routes {
			switch route {
			case tsaddr.AllIPv4():
				default4 = true
			case tsaddr.AllIPv6():
				default6 = true
			}
			if default4 && default6 {
				break
			}
		}
		if !default4 {
			rs.Routes = append(rs.Routes, tsaddr.AllIPv4())
		}
		if !default6 {
			rs.Routes = append(rs.Routes, tsaddr.AllIPv6())
		}
		internalIPs, externalIPs, err := internalAndExternalInterfaces()
		if err != nil {
			b.logf("failed to discover interface ips: %v", err)
		}
		switch runtime.GOOS {
		case "linux", "windows", "darwin", "ios", "android":
			rs.LocalRoutes = internalIPs // unconditionally allow access to guest VM networks
			if prefs.ExitNodeAllowLANAccess() {
				rs.LocalRoutes = append(rs.LocalRoutes, externalIPs...)
			} else {
				// Explicitly add routes to the local network so that we do not
				// leak any traffic.
				rs.Routes = append(rs.Routes, externalIPs...)
			}
			b.logf("allowing exit node access to local IPs: %v", rs.LocalRoutes)
		default:
			if prefs.ExitNodeAllowLANAccess() {
				b.logf("warning: ExitNodeAllowLANAccess has no effect on " + runtime.GOOS)
			}
		}
	}

	if slices.ContainsFunc(rs.LocalAddrs, tsaddr.PrefixIs4) {
		rs.Routes = append(rs.Routes, netip.PrefixFrom(tsaddr.TailscaleServiceIP(), 32))
	}
	if slices.ContainsFunc(rs.LocalAddrs, tsaddr.PrefixIs6) {
		rs.Routes = append(rs.Routes, netip.PrefixFrom(tsaddr.TailscaleServiceIPv6(), 128))
	}

	return rs
}

func unmapIPPrefix(ipp netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(ipp.Addr().Unmap(), ipp.Bits())
}

func unmapIPPrefixes(ippsList ...[]netip.Prefix) (ret []netip.Prefix) {
	for _, ipps := range ippsList {
		for _, ipp := range ipps {
			ret = append(ret, unmapIPPrefix(ipp))
		}
	}
	return ret
}

// b.mu must be held.
func (b *LocalBackend) applyPrefsToHostinfoLocked(hi *tailcfg.Hostinfo, prefs ipn.PrefsView) {
	if h := prefs.Hostname(); h != "" {
		hi.Hostname = h
	}
	hi.RoutableIPs = prefs.AdvertiseRoutes().AsSlice()
	hi.RequestTags = prefs.AdvertiseTags().AsSlice()
	hi.ShieldsUp = prefs.ShieldsUp()
	hi.AllowsUpdate = envknob.AllowsRemoteUpdate() || prefs.AutoUpdate().Apply.EqualBool(true)

	b.metrics.advertisedRoutes.Set(float64(tsaddr.WithoutExitRoute(prefs.AdvertiseRoutes()).Len()))

	hi.ServicesHash = b.vipServiceHash(b.vipServicesFromPrefsLocked(prefs))

	// The Hostinfo.WantIngress field tells control whether this node wants to
	// be wired up for ingress connections. If harmless if it's accidentally
	// true; the actual policy is controlled in tailscaled by ServeConfig. But
	// if this is accidentally false, then control may not configure DNS
	// properly. This exists as an optimization to control to program fewer DNS
	// records that have ingress enabled but are not actually being used.
	hi.WireIngress = false
	hi.AppConnector.Set(prefs.AppConnector().Advertise)
}

// enterState transitions the backend into newState, updating internal
// state and propagating events out as needed.
//
// TODO(danderson): while this isn't a lie, exactly, a ton of other
// places twiddle IPN internal state without going through here, so
// really this is more "one of several places in which random things
// happen".
func (b *LocalBackend) enterState(newState ipn.State) {
	unlock := b.lockAndGetUnlock()
	b.enterStateLockedOnEntry(newState, unlock)
}

// enterStateLockedOnEntry is like enterState but requires b.mu be held to call
// it, but it unlocks b.mu when done (via unlock, a once func).
func (b *LocalBackend) enterStateLockedOnEntry(newState ipn.State, unlock unlockOnce) {
	oldState := b.state
	b.state = newState
	prefs := b.pm.CurrentPrefs()

	// Some temporary (2024-05-05) debugging code to help us catch
	// https://github.com/tailscale/tailscale/issues/11962 in the act.
	if prefs.WantRunning() &&
		prefs.ControlURLOrDefault() == ipn.DefaultControlURL &&
		envknob.Bool("TS_PANIC_IF_HIT_MAIN_CONTROL") {
		panic("[unexpected] use of main control server in integration test")
	}

	netMap := b.netMap
	authURL := b.authURL
	if newState == ipn.Running {
		b.resetAuthURLLocked()

		// Start a captive portal detection loop if none has been
		// started. Create a new context if none is present, since it
		// can be shut down if we transition away from Running.
		if b.captiveCancel == nil {
			b.captiveCtx, b.captiveCancel = context.WithCancel(b.ctx)
			b.goTracker.Go(func() { b.checkCaptivePortalLoop(b.captiveCtx) })
		}
	} else if oldState == ipn.Running {
		// Transitioning away from running.

		// Stop any existing captive portal detection loop.
		if b.captiveCancel != nil {
			b.captiveCancel()
			b.captiveCancel = nil

			// NOTE: don't set captiveCtx to nil here, to ensure
			// that we always have a (canceled) context to wait on
			// in onHealthChange.
		}
	}
	b.pauseOrResumeControlClientLocked()

	unlock.UnlockEarly()

	// prefs may change irrespective of state; WantRunning should be explicitly
	// set before potential early return even if the state is unchanged.
	b.health.SetIPNState(newState.String(), prefs.Valid() && prefs.WantRunning())
	if oldState == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)",
		oldState, newState, prefs.WantRunning(), netMap != nil)
	b.send(ipn.Notify{State: &newState})

	switch newState {
	case ipn.NeedsLogin:
		if b.seamlessRenewalEnabled() {
			break
		}
		b.blockEngineUpdates(true)
		fallthrough
	case ipn.Stopped:
		err := b.e.Reconfig(&wgcfg.Config{}, &router.Config{})
		if err != nil {
			b.logf("Reconfig(down): %v", err)
		}

		if authURL == "" {
		}
	case ipn.Starting, ipn.NeedsMachineAuth:
		b.authReconfig()
		// Needed so that UpdateEndpoints can run
		b.e.RequestStatus()
	case ipn.Running:
	case ipn.NoState:
		// Do nothing.
	default:
		b.logf("[unexpected] unknown newState %#v", newState)
	}
}

func (b *LocalBackend) hasNodeKeyLocked() bool {
	// we can't use b.Prefs(), because it strips the keys, oops!
	p := b.pm.CurrentPrefs()
	return p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero()
}

// NodeKey returns the public node key.
func (b *LocalBackend) NodeKey() key.NodePublic {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.hasNodeKeyLocked() {
		return key.NodePublic{}
	}
	return b.pm.CurrentPrefs().Persist().PublicNodeKey()
}

// nextStateLocked returns the state the backend seems to be in, based on
// its internal state.
//
// b.mu must be held
func (b *LocalBackend) nextStateLocked() ipn.State {
	var (
		cc         = b.cc
		netMap     = b.netMap
		state      = b.state
		blocked    = b.blocked
		st         = b.engineStatus
		keyExpired = b.keyExpired

		wantRunning = false
		loggedOut   = false
	)
	if p := b.pm.CurrentPrefs(); p.Valid() {
		wantRunning = p.WantRunning()
		loggedOut = p.LoggedOut()
	}

	switch {
	case !wantRunning && !loggedOut && !blocked && b.hasNodeKeyLocked():
		return ipn.Stopped
	case netMap == nil:
		if (cc != nil && cc.AuthCantContinue()) || loggedOut {
			// Auth was interrupted or waiting for URL visit,
			// so it won't proceed without human help.
			return ipn.NeedsLogin
		}
		switch state {
		case ipn.Stopped:
			// If we were already in the Stopped state, then
			// we can assume auth is in good shape (or we would
			// have been in NeedsLogin), so transition to Starting
			// right away.
			return ipn.Starting
		case ipn.NoState:
			// Our first time connecting to control, and we
			// don't know if we'll NeedsLogin or not yet.
			// UIs should print "Loading..." in this state.
			return ipn.NoState
		case ipn.Starting, ipn.Running, ipn.NeedsLogin:
			return state
		default:
			b.logf("unexpected no-netmap state transition for %v", state)
			return state
		}
	case !wantRunning:
		return ipn.Stopped
	case keyExpired:
		// NetMap must be non-nil for us to get here.
		// The node key expired, need to relogin.
		return ipn.NeedsLogin
	case netMap.GetMachineStatus() != tailcfg.MachineAuthorized:
		// TODO(crawshaw): handle tailcfg.MachineInvalid
		return ipn.NeedsMachineAuth
	case state == ipn.NeedsMachineAuth:
		// (if we get here, we know MachineAuthorized == true)
		return ipn.Starting
	case state == ipn.Starting:
		if st.NumLive > 0 || st.LiveDERPs > 0 {
			return ipn.Running
		} else {
			return state
		}
	case state == ipn.Running:
		return ipn.Running
	default:
		return ipn.Starting
	}
}

// stateMachine updates the state machine state based on other things
// that have happened. It is invoked from the various callbacks that
// feed events into LocalBackend.
//
// TODO(apenwarr): use a channel or something to prevent reentrancy?
// Or maybe just call the state machine from fewer places.
func (b *LocalBackend) stateMachine() {
	unlock := b.lockAndGetUnlock()
	b.stateMachineLockedOnEntry(unlock)
}

// stateMachineLockedOnEntry is like stateMachine but requires b.mu be held to
// call it, but it unlocks b.mu when done (via unlock, a once func).
func (b *LocalBackend) stateMachineLockedOnEntry(unlock unlockOnce) {
	b.enterStateLockedOnEntry(b.nextStateLocked(), unlock)
}

// lockAndGetUnlock locks b.mu and returns a sync.OnceFunc function that will
// unlock it at most once.
//
// This is all very unfortunate but exists as a guardrail against the
// unfortunate "lockedOnEntry" methods in this package (primarily
// enterStateLockedOnEntry) that require b.mu held to be locked on entry to the
// function but unlock the mutex on their way out. As a stepping stone to
// cleaning things up (as of 2024-04-06), we at least pass the unlock func
// around now and defer unlock in the caller to avoid missing unlocks and double
// unlocks. TODO(bradfitz,maisem): make the locking in this package more
// traditional (simple). See https://github.com/tailscale/tailscale/issues/11649
func (b *LocalBackend) lockAndGetUnlock() (unlock unlockOnce) {
	b.mu.Lock()
	var unlocked atomic.Bool
	return func() bool {
		if unlocked.CompareAndSwap(false, true) {
			b.mu.Unlock()
			return true
		}
		return false
	}
}

// unlockOnce is a func that unlocks only b.mu the first time it's called.
// Therefore it can be safely deferred to catch error paths, without worrying
// about double unlocks if a different point in the code later needs to explicitly
// unlock it first as well. It reports whether it was unlocked.
type unlockOnce func() bool

// UnlockEarly unlocks the LocalBackend.mu. It panics if u returns false,
// indicating that this unlocker was already used.
//
// We're using this method to help us document & find the places that have
// atypical locking patterns. See
// https://github.com/tailscale/tailscale/issues/11649 for background.
//
// A normal unlock is a deferred one or an explicit b.mu.Unlock a few lines
// after the lock, without lots of control flow in-between. An "early" unlock is
// one that happens in weird places, like in various "LockedOnEntry" methods in
// this package that require the mutex to be locked on entry but unlock it
// somewhere in the middle (maybe several calls away) and then sometimes proceed
// to lock it again.
//
// The reason UnlockeEarly panics if already called is because these are the
// points at which it's assumed that the mutex is already held and it now needs
// to be released. If somebody already released it, that invariant was violated.
// On the other hand, simply calling u only returns false instead of panicking
// so you can defer it without care, confident you got all the error return
// paths which were previously done by hand.
func (u unlockOnce) UnlockEarly() {
	if !u() {
		panic("Unlock on already-called unlockOnce")
	}
}

// stopEngineAndWait deconfigures the local network data plane, and
// waits for it to deliver a status update before returning.
//
// TODO(danderson): this may be racy. We could unblock upon receiving
// a status update that predates the "I've shut down" update.
func (b *LocalBackend) stopEngineAndWait() {
	b.logf("stopEngineAndWait...")
	b.e.Reconfig(&wgcfg.Config{}, &router.Config{})
	b.requestEngineStatusAndWait()
	b.logf("stopEngineAndWait: done.")
}

// Requests the wgengine status, and does not return until the status
// was delivered (to the usual callback).
func (b *LocalBackend) requestEngineStatusAndWait() {
	b.logf("requestEngineStatusAndWait")

	b.statusLock.Lock()
	defer b.statusLock.Unlock()

	b.goTracker.Go(b.e.RequestStatus)
	b.logf("requestEngineStatusAndWait: waiting...")
	b.statusChanged.Wait() // temporarily releases lock while waiting
	b.logf("requestEngineStatusAndWait: got status update.")
}

// setControlClientLocked sets the control client to cc,
// which may be nil.
//
// b.mu must be held.
func (b *LocalBackend) setControlClientLocked(cc controlclient.Client) {
	b.cc = cc
	b.ccAuto, _ = cc.(*controlclient.Auto)
}

// resetControlClientLocked sets b.cc to nil and returns the old value. If the
// returned value is non-nil, the caller must call Shutdown on it after
// releasing b.mu.
func (b *LocalBackend) resetControlClientLocked() controlclient.Client {
	if b.cc == nil {
		return nil
	}

	b.resetAuthURLLocked()

	// When we clear the control client, stop any outstanding netmap expiry
	// timer; synthesizing a new netmap while we don't have a control
	// client will break things.
	//
	// See https://github.com/tailscale/tailscale/issues/7392
	if b.nmExpiryTimer != nil {
		b.nmExpiryTimer.Stop()
		b.nmExpiryTimer = nil

		// Also bump the epoch to ensure that if the timer started, it
		// will abort.
		b.numClientStatusCalls.Add(1)
	}
	prev := b.cc
	b.setControlClientLocked(nil)
	return prev
}

// resetAuthURLLocked resets authURL, canceling any pending interactive login.
func (b *LocalBackend) resetAuthURLLocked() {
	b.authURL = ""
	b.authURLTime = time.Time{}
	b.authActor = nil
}

// ResetForClientDisconnect resets the backend for GUI clients running
// in interactive (non-headless) mode. This is currently used only by
// Windows. This causes all state to be cleared, lest an unrelated user
// connect to tailscaled next. But it does not trigger a logout; we
// don't want to the user to have to reauthenticate in the future
// when they restart the GUI.
func (b *LocalBackend) ResetForClientDisconnect() {
	b.logf("LocalBackend.ResetForClientDisconnect")

	unlock := b.lockAndGetUnlock()
	defer unlock()

	prevCC := b.resetControlClientLocked()
	if prevCC != nil {
		// Needs to happen without b.mu held.
		defer prevCC.Shutdown()
	}

	b.setNetMapLocked(nil)
	b.pm.Reset()
	if b.currentUser != nil {
		if c, ok := b.currentUser.(ipnauth.ActorCloser); ok {
			c.Close()
		}
		b.currentUser = nil
	}
	b.keyExpired = false
	b.resetAuthURLLocked()
	b.activeLogin = ""
	b.resetDialPlan()
	b.setAtomicValuesFromPrefsLocked(ipn.PrefsView{})
	b.enterStateLockedOnEntry(ipn.Stopped, unlock)
}

func (b *LocalBackend) ShouldRunSSH() bool { return b.sshAtomicBool.Load() && envknob.CanSSHD() }

// ShouldHandleViaIP reports whether ip is an IPv6 address in the
// Tailscale ULA's v6 "via" range embedding an IPv4 address to be forwarded to
// by Tailscale.
func (b *LocalBackend) ShouldHandleViaIP(ip netip.Addr) bool {
	if f, ok := b.containsViaIPFuncAtomic.LoadOk(); ok {
		return f(ip)
	}
	return false
}

// Logout logs out the current profile, if any, and waits for the logout to
// complete.
func (b *LocalBackend) Logout(ctx context.Context) error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	if !b.hasNodeKeyLocked() {
		// Already logged out.
		return nil
	}
	cc := b.cc

	// Grab the current profile before we unlock the mutex, so that we can
	// delete it later.
	profile := b.pm.CurrentProfile()

	_, err := b.editPrefsLockedOnEntry(&ipn.MaskedPrefs{
		WantRunningSet: true,
		LoggedOutSet:   true,
		Prefs:          ipn.Prefs{WantRunning: false, LoggedOut: true},
	}, unlock)
	if err != nil {
		return err
	}
	// b.mu is now unlocked, after editPrefsLockedOnEntry.

	// Clear any previous dial plan(s), if set.
	b.resetDialPlan()

	if cc == nil {
		// Double Logout can happen via repeated IPN
		// connections to ipnserver making it repeatedly
		// transition from 1->0 total connections, which on
		// Windows by default ("client mode") causes a Logout
		// on the transition to zero.
		// Previously this crashed when we asserted that c was non-nil
		// here.
		return errors.New("no controlclient")
	}

	if err := cc.Logout(ctx); err != nil {
		return err
	}

	unlock = b.lockAndGetUnlock()
	defer unlock()

	if err := b.pm.DeleteProfile(profile.ID); err != nil {
		b.logf("error deleting profile: %v", err)
		return err
	}
	return b.resetForProfileChangeLockedOnEntry(unlock)
}

// setNetInfo sets b.hostinfo.NetInfo to ni, and passes ni along to the
// controlclient, if one exists.
func (b *LocalBackend) setNetInfo(ni *tailcfg.NetInfo) {
	b.mu.Lock()
	cc := b.cc
	var refresh bool
	if b.MagicConn().DERPs() > 0 || testenv.InTest() {
		// When b.refreshAutoExitNode is set, we recently observed a link change
		// that indicates we have switched networks. After switching networks,
		// the previously selected automatic exit node is no longer as likely
		// to be a good choice and connectivity will already be broken due to
		// the network switch. Therefore, it is a good time to switch to a new
		// exit node because the network is already disrupted.
		//
		// Unfortunately, at the time of the link change, no information is
		// known about the new network's latency or location, so the necessary
		// details are not available to make a new choice. Instead, it sets
		// b.refreshAutoExitNode to signal that a new decision should be made
		// when we have an updated netcheck report. ni is that updated report.
		//
		// However, during testing we observed that often the first ni is
		// inconclusive because it was running during the link change or the
		// link was otherwise not stable yet. b.MagicConn().updateEndpoints()
		// can detect when the netcheck failed and trigger a rebind, but the
		// required information is not available here, and moderate additional
		// plumbing is required to pass that in. Instead, checking for an active
		// DERP link offers an easy approximation. We will continue to refine
		// this over time.
		refresh = b.refreshAutoExitNode
		b.refreshAutoExitNode = false
	}
	b.mu.Unlock()

	if cc == nil {
		return
	}
	cc.SetNetInfo(ni)
	if refresh {
		unlock := b.lockAndGetUnlock()
		defer unlock()
		b.setAutoExitNodeIDLockedOnEntry(unlock)
	}
}

func (b *LocalBackend) setAutoExitNodeIDLockedOnEntry(unlock unlockOnce) (newPrefs ipn.PrefsView) {
	var zero ipn.PrefsView
	defer unlock()

	prefs := b.pm.CurrentPrefs()
	if !prefs.Valid() {
		b.logf("[unexpected]: received tailnet exit node ID pref change callback but current prefs are nil")
		return zero
	}
	prefsClone := prefs.AsStruct()
	newSuggestion, err := b.suggestExitNodeLocked(nil)
	if err != nil {
		b.logf("setAutoExitNodeID: %v", err)
		return zero
	}
	if prefsClone.ExitNodeID == newSuggestion.ID {
		return zero
	}
	prefsClone.ExitNodeID = newSuggestion.ID
	newPrefs, err = b.editPrefsLockedOnEntry(&ipn.MaskedPrefs{
		Prefs:         *prefsClone,
		ExitNodeIDSet: true,
	}, unlock)
	if err != nil {
		b.logf("setAutoExitNodeID: failed to apply exit node ID preference: %v", err)
		return zero
	}
	return newPrefs
}

// setNetMapLocked updates the LocalBackend state to reflect the newly
// received nm. If nm is nil, it resets all configuration as though
// Tailscale is turned off.
func (b *LocalBackend) setNetMapLocked(nm *netmap.NetworkMap) {
	b.dialer.SetNetMap(nm)
	if ns, ok := b.sys.Netstack.GetOK(); ok {
		ns.UpdateNetstackIPs(nm)
	}
	var login string
	if nm != nil {
		login = cmp.Or(nm.UserProfiles[nm.User()].LoginName, "<missing-profile>")
	}
	b.netMap = nm
	b.updatePeersFromNetmapLocked(nm)
	if login != b.activeLogin {
		b.logf("active login: %v", login)
		b.activeLogin = login
	}
	b.pauseOrResumeControlClientLocked()

	if nm != nil {
		b.health.SetControlHealth(nm.ControlHealth)
	} else {
		b.health.SetControlHealth(nil)
	}

	// Determine if file sharing is enabled
	fs := nm.HasCap(tailcfg.CapabilityFileSharing)
	if fs != b.capFileSharing {
	}
	b.capFileSharing = fs

	if nm.HasCap(tailcfg.NodeAttrLinuxMustUseIPTables) {
		b.capForcedNetfilter = "iptables"
	} else if nm.HasCap(tailcfg.NodeAttrLinuxMustUseNfTables) {
		b.capForcedNetfilter = "nftables"
	} else {
		b.capForcedNetfilter = "" // empty string means client can auto-detect
	}

	b.MagicConn().SetSilentDisco(b.ControlKnobs().SilentDisco.Load())
	b.MagicConn().SetProbeUDPLifetime(b.ControlKnobs().ProbeUDPLifetime.Load())

	b.setDebugLogsByCapabilityLocked(nm)

	// See the netns package for documentation on what this capability does.
	netns.SetBindToInterfaceByRoute(nm.HasCap(tailcfg.CapabilityBindToInterfaceByRoute))
	netns.SetDisableBindConnToInterface(nm.HasCap(tailcfg.CapabilityDebugDisableBindConnToInterface))

	if nm == nil {
		b.nodeByAddr = nil

		// If there is no netmap, the client is going into a "turned off"
		// state so reset the metrics.
		b.metrics.approvedRoutes.Set(0)
		return
	}

	// Update the nodeByAddr index.
	if b.nodeByAddr == nil {
		b.nodeByAddr = map[netip.Addr]tailcfg.NodeID{}
	}
	// First pass, mark everything unwanted.
	for k := range b.nodeByAddr {
		b.nodeByAddr[k] = 0
	}
	addNode := func(n tailcfg.NodeView) {
		for _, ipp := range n.Addresses().All() {
			if ipp.IsSingleIP() {
				b.nodeByAddr[ipp.Addr()] = n.ID()
			}
		}
	}
	if nm.SelfNode.Valid() {
		addNode(nm.SelfNode)

		var approved float64
		for _, route := range nm.SelfNode.AllowedIPs().All() {
			if !views.SliceContains(nm.SelfNode.Addresses(), route) && !tsaddr.IsExitRoute(route) {
				approved++
			}
		}
		b.metrics.approvedRoutes.Set(approved)
	}
	for _, p := range nm.Peers {
		addNode(p)
	}
	// Third pass, actually delete the unwanted items.
	for k, v := range b.nodeByAddr {
		if v == 0 {
			delete(b.nodeByAddr, k)
		}
	}
}

func (b *LocalBackend) updatePeersFromNetmapLocked(nm *netmap.NetworkMap) {
	if nm == nil {
		b.peers = nil
		return
	}

	// First pass, mark everything unwanted.
	for k := range b.peers {
		b.peers[k] = tailcfg.NodeView{}
	}

	// Second pass, add everything wanted.
	for _, p := range nm.Peers {
		mak.Set(&b.peers, p.ID(), p)
	}

	// Third pass, remove deleted things.
	for k, v := range b.peers {
		if !v.Valid() {
			delete(b.peers, k)
		}
	}
}

// setDebugLogsByCapabilityLocked sets debug logging based on the self node's
// capabilities in the provided NetMap.
func (b *LocalBackend) setDebugLogsByCapabilityLocked(nm *netmap.NetworkMap) {
}

// operatorUserName returns the current pref's OperatorUser's name, or the
// empty string if none.
func (b *LocalBackend) operatorUserName() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	prefs := b.pm.CurrentPrefs()
	if !prefs.Valid() {
		return ""
	}
	return prefs.OperatorUser()
}

// OperatorUserID returns the current pref's OperatorUser's ID (in
// os/user.User.Uid string form), or the empty string if none.
func (b *LocalBackend) OperatorUserID() string {
	opUserName := b.operatorUserName()
	if opUserName == "" {
		return ""
	}
	u, err := osuser.LookupByUsername(opUserName)
	if err != nil {
		b.logf("error looking up operator %q uid: %v", opUserName, err)
		return ""
	}
	return u.Uid
}

// TestOnlyPublicKeys returns the current machine and node public
// keys. Used in tests only to facilitate automated node authorization
// in the test harness.
func (b *LocalBackend) TestOnlyPublicKeys() (machineKey key.MachinePublic, nodeKey key.NodePublic) {
	b.mu.Lock()
	machinePrivKey := b.machinePrivKey
	prefs := b.pm.CurrentPrefs()
	b.mu.Unlock()

	if !prefs.Valid() || machinePrivKey.IsZero() {
		return
	}

	mk := machinePrivKey.Public()
	nk := prefs.Persist().PublicNodeKey()
	return mk, nk
}

func (b *LocalBackend) peerHasCapLocked(addr netip.Addr, wantCap tailcfg.PeerCapability) bool {
	return b.peerCapsLocked(addr).HasCapability(wantCap)
}

func peerAPIPorts(peer tailcfg.NodeView) (p4, p6 uint16) {
	svcs := peer.Hostinfo().Services()
	for _, s := range svcs.All() {
		switch s.Proto {
		case tailcfg.PeerAPI4:
			p4 = s.Port
		case tailcfg.PeerAPI6:
			p6 = s.Port
		}
	}
	return
}

// peerAPIURL returns an HTTP URL for the peer's peerapi service,
// without a trailing slash.
//
// If ip or port is the zero value then it returns the empty string.
func peerAPIURL(ip netip.Addr, port uint16) string {
	if port == 0 || !ip.IsValid() {
		return ""
	}
	return fmt.Sprintf("http://%v", netip.AddrPortFrom(ip, port))
}

// peerAPIBase returns the "http://ip:port" URL base to reach peer's peerAPI.
// It returns the empty string if the peer doesn't support the peerapi
// or there's no matching address family based on the netmap's own addresses.
func peerAPIBase(nm *netmap.NetworkMap, peer tailcfg.NodeView) string {
	if nm == nil || !peer.Valid() || !peer.Hostinfo().Valid() {
		return ""
	}

	var have4, have6 bool
	addrs := nm.GetAddresses()
	for _, a := range addrs.All() {
		if !a.IsSingleIP() {
			continue
		}
		switch {
		case a.Addr().Is4():
			have4 = true
		case a.Addr().Is6():
			have6 = true
		}
	}
	p4, p6 := peerAPIPorts(peer)
	switch {
	case have4 && p4 != 0:
		return peerAPIURL(nodeIP(peer, netip.Addr.Is4), p4)
	case have6 && p6 != 0:
		return peerAPIURL(nodeIP(peer, netip.Addr.Is6), p6)
	}
	return ""
}

func nodeIP(n tailcfg.NodeView, pred func(netip.Addr) bool) netip.Addr {
	for _, pfx := range n.Addresses().All() {
		if pfx.IsSingleIP() && pred(pfx.Addr()) {
			return pfx.Addr()
		}
	}
	return netip.Addr{}
}

func (b *LocalBackend) CheckIPForwarding() error {
	if b.sys.IsNetstackRouter() {
		return nil
	}

	// TODO: let the caller pass in the ranges.
	warn, err := netutil.CheckIPForwarding(tsaddr.ExitRoutes(), b.sys.NetMon.Get().InterfaceState())
	if err != nil {
		return err
	}
	return warn
}

// DERPMap returns the current DERPMap in use, or nil if not connected.
func (b *LocalBackend) DERPMap() *tailcfg.DERPMap {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.netMap == nil {
		return nil
	}
	return b.netMap.DERPMap
}

// OfferingExitNode reports whether b is currently offering exit node
// access.
func (b *LocalBackend) OfferingExitNode() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.pm.CurrentPrefs().Valid() {
		return false
	}
	var def4, def6 bool
	ar := b.pm.CurrentPrefs().AdvertiseRoutes()
	for i := range ar.Len() {
		r := ar.At(i)
		if r.Bits() != 0 {
			continue
		}
		if r.Addr().Is4() {
			def4 = true
		} else if r.Addr().Is6() {
			def6 = true
		}
	}
	return def4 && def6
}

// allowExitNodeDNSProxyToServeName reports whether the Exit Node DNS
// proxy is allowed to serve responses for the provided DNS name.
func (b *LocalBackend) allowExitNodeDNSProxyToServeName(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	nm := b.netMap
	if nm == nil {
		return false
	}
	name = strings.ToLower(name)
	for _, bad := range nm.DNS.ExitNodeFilteredSet {
		if bad == "" {
			// Invalid, ignore.
			continue
		}
		if bad[0] == '.' {
			// Entries beginning with a dot are suffix matches.
			if dnsname.HasSuffix(name, bad) {
				return false
			}
			continue
		}
		// Otherwise entries are exact matches. They're
		// guaranteed to be lowercase already.
		if name == bad {
			return false
		}
	}
	return true
}

// SetExpiry updates the expiry of the current node key to t, as long as it's
// only sooner than the old expiry.
//
// If t is in the past, the key is expired immediately.
// If t is after the current expiry, an error is returned.
func (b *LocalBackend) SetExpirySooner(ctx context.Context, expiry time.Time) error {
	b.mu.Lock()
	cc := b.ccAuto
	b.mu.Unlock()
	if cc == nil {
		return errors.New("not running")
	}
	return cc.SetExpirySooner(ctx, expiry)
}

// SetDeviceAttrs does a synchronous call to the control plane to update
// the node's attributes.
//
// See docs on [tailcfg.SetDeviceAttributesRequest] for background.
func (b *LocalBackend) SetDeviceAttrs(ctx context.Context, attrs tailcfg.AttrUpdate) error {
	b.mu.Lock()
	cc := b.ccAuto
	b.mu.Unlock()
	if cc == nil {
		return errors.New("not running")
	}
	return cc.SetDeviceAttrs(ctx, attrs)
}

// exitNodeCanProxyDNS reports the DoH base URL ("http://foo/dns-query") without query parameters
// to exitNodeID's DoH service, if available.
//
// If exitNodeID is the zero valid, it returns "", false.
func exitNodeCanProxyDNS(nm *netmap.NetworkMap, peers map[tailcfg.NodeID]tailcfg.NodeView, exitNodeID tailcfg.StableNodeID) (dohURL string, ok bool) {
	if exitNodeID.IsZero() {
		return "", false
	}
	for _, p := range peers {
		if p.StableID() == exitNodeID && peerCanProxyDNS(p) {
			return peerAPIBase(nm, p) + "/dns-query", true
		}
	}
	return "", false
}

// wireguardExitNodeDNSResolvers returns the DNS resolvers to use for a
// WireGuard-only exit node, if it has resolver addresses.
func wireguardExitNodeDNSResolvers(nm *netmap.NetworkMap, peers map[tailcfg.NodeID]tailcfg.NodeView, exitNodeID tailcfg.StableNodeID) ([]*dnstype.Resolver, bool) {
	if exitNodeID.IsZero() {
		return nil, false
	}

	for _, p := range peers {
		if p.StableID() == exitNodeID {
			if p.IsWireGuardOnly() {
				resolvers := p.ExitNodeDNSResolvers()
				if !resolvers.IsNil() && resolvers.Len() > 0 {
					copies := make([]*dnstype.Resolver, resolvers.Len())
					for i, r := range resolvers.All() {
						copies[i] = r.AsStruct()
					}
					return copies, true
				}
			}
			return nil, false
		}
	}

	return nil, false
}

func peerCanProxyDNS(p tailcfg.NodeView) bool {
	if p.Cap() >= 26 {
		// Actually added at 25
		// (https://github.com/tailscale/tailscale/blob/3ae6f898cfdb58fd0e30937147dd6ce28c6808dd/tailcfg/tailcfg.go#L51)
		// so anything >= 26 can do it.
		return true
	}
	// If p.Cap is not populated (e.g. older control server), then do the old
	// thing of searching through services.
	services := p.Hostinfo().Services()
	for _, s := range services.All() {
		if s.Proto == tailcfg.PeerAPIDNS && s.Port >= 1 {
			return true
		}
	}
	return false
}

func (b *LocalBackend) DebugRebind() error {
	b.MagicConn().Rebind()
	return nil
}

func (b *LocalBackend) DebugReSTUN() error {
	b.MagicConn().ReSTUN("explicit-debug")
	return nil
}

// ControlKnobs returns the node's control knobs.
func (b *LocalBackend) ControlKnobs() *controlknobs.Knobs {
	return b.sys.ControlKnobs()
}

// MagicConn returns the backend's *magicsock.Conn.
func (b *LocalBackend) MagicConn() *magicsock.Conn {
	return b.sys.MagicSock.Get()
}

type keyProvingNoiseRoundTripper struct {
	b *LocalBackend
}

func (n keyProvingNoiseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	b := n.b

	var priv key.NodePrivate

	b.mu.Lock()
	cc := b.ccAuto
	if nm := b.netMap; nm != nil {
		priv = nm.PrivateKey
	}
	b.mu.Unlock()
	if cc == nil {
		return nil, errors.New("no client")
	}
	if priv.IsZero() {
		return nil, errors.New("no netmap or private key")
	}
	rt, ep, err := cc.GetSingleUseNoiseRoundTripper(req.Context())
	if err != nil {
		return nil, err
	}
	if ep == nil || ep.NodeKeyChallenge.IsZero() {
		go rt.RoundTrip(new(http.Request)) // return our reservation with a bogus request
		return nil, errors.New("this coordination server does not support API calls over the Noise channel")
	}

	// QueryEscape the node key since it has a colon in it.
	nk := url.QueryEscape(priv.Public().String())
	req.SetBasicAuth(nk, "")

	// genNodeProofHeaderValue returns the Tailscale-Node-Proof header's value to prove
	// to chalPub that we control claimedPrivate.
	genNodeProofHeaderValue := func(claimedPrivate key.NodePrivate, chalPub key.ChallengePublic) string {
		// TODO(bradfitz): cache this somewhere?
		box := claimedPrivate.SealToChallenge(chalPub, []byte(chalPub.String()))
		return claimedPrivate.Public().String() + " " + base64.StdEncoding.EncodeToString(box)
	}

	// And prove we have the private key corresponding to the public key sent
	// tin the basic auth username.
	req.Header.Set("Tailscale-Node-Proof", genNodeProofHeaderValue(priv, ep.NodeKeyChallenge))

	return rt.RoundTrip(req)
}

// KeyProvingNoiseRoundTripper returns an http.RoundTripper that uses the LocalBackend's
// DoNoiseRequest method and mutates the request to add an authorization header
// to prove the client's nodekey.
func (b *LocalBackend) KeyProvingNoiseRoundTripper() http.RoundTripper {
	return keyProvingNoiseRoundTripper{b}
}

// DoNoiseRequest sends a request to URL over the control plane
// Noise connection.
func (b *LocalBackend) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	b.mu.Lock()
	cc := b.ccAuto
	b.mu.Unlock()
	if cc == nil {
		return nil, errors.New("no client")
	}
	return cc.DoNoiseRequest(req)
}

func (b *LocalBackend) sshServerOrInit() (_ SSHServer, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sshServer != nil {
		return b.sshServer, nil
	}
	if newSSHServer == nil {
		return nil, errors.New("no SSH server support")
	}
	b.sshServer, err = newSSHServer(b.logf, b)
	if err != nil {
		return nil, fmt.Errorf("newSSHServer: %w", err)
	}
	return b.sshServer, nil
}

var warnSSHSELinuxWarnable = health.Register(&health.Warnable{
	Code:     "ssh-unavailable-selinux-enabled",
	Title:    "Tailscale SSH and SELinux",
	Severity: health.SeverityLow,
	Text:     health.StaticMessage("SELinux is enabled; Tailscale SSH may not work. See https://tailscale.com/s/ssh-selinux"),
})

func (b *LocalBackend) updateSELinuxHealthWarning() {
	if hostinfo.IsSELinuxEnforcing() {
		b.health.SetUnhealthy(warnSSHSELinuxWarnable, nil)
	} else {
		b.health.SetHealthy(warnSSHSELinuxWarnable)
	}
}

func (b *LocalBackend) handleSSHConn(c net.Conn) (err error) {
	s, err := b.sshServerOrInit()
	if err != nil {
		return err
	}
	b.updateSELinuxHealthWarning()
	return s.HandleSSHConn(c)
}

// HandleQuad100Port80Conn serves http://100.100.100.100/ on port 80 (and
// the equivalent tsaddr.TailscaleServiceIPv6 address).
func (b *LocalBackend) HandleQuad100Port80Conn(c net.Conn) error {
	var s http.Server
	s.Handler = http.HandlerFunc(b.handleQuad100Port80Conn)
	return s.Serve(netutil.NewOneConnListener(c, nil))
}

func validQuad100Host(h string) bool {
	switch h {
	case "",
		tsaddr.TailscaleServiceIPString,
		tsaddr.TailscaleServiceIPv6String,
		"[" + tsaddr.TailscaleServiceIPv6String + "]":
		return true
	}
	return false
}

func (b *LocalBackend) handleQuad100Port80Conn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self';")
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validQuad100Host(r.Host) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	io.WriteString(w, "<h1>Tailscale</h1>\n")
	if b.netMap == nil {
		io.WriteString(w, "No netmap.\n")
		return
	}
	addrs := b.netMap.GetAddresses()
	if addrs.Len() == 0 {
		io.WriteString(w, "No local addresses.\n")
		return
	}
	io.WriteString(w, "<p>Local addresses:</p><ul>\n")
	for i := range addrs.Len() {
		fmt.Fprintf(w, "<li>%v</li>\n", addrs.At(i).Addr())
	}
	io.WriteString(w, "</ul>\n")
}

// SetDevStateStore updates the LocalBackend's state storage to the provided values.
//
// It's meant only for development.
func (b *LocalBackend) SetDevStateStore(key, value string) error {
	if b.store == nil {
		return errors.New("no state store")
	}
	err := ipn.WriteState(b.store, ipn.StateKey(key), []byte(value))
	b.logf("SetDevStateStore(%q, %q) = %v", key, value, err)

	if err != nil {
		return err
	}

	return nil
}

// ShouldInterceptTCPPort reports whether the given TCP port number to a
// Tailscale IP (not a subnet router, service IP, etc) should be intercepted by
// Tailscaled and handled in-process.
func (b *LocalBackend) ShouldInterceptTCPPort(port uint16) bool {
	return b.shouldInterceptTCPPortAtomic.Load()(port)
}

// SwitchProfile switches to the profile with the given id.
// It will restart the backend on success.
// If the profile is not known, it returns an errProfileNotFound.
func (b *LocalBackend) SwitchProfile(profile ipn.ProfileID) error {
	if b.CurrentProfile().ID == profile {
		return nil
	}
	unlock := b.lockAndGetUnlock()
	defer unlock()

	oldControlURL := b.pm.CurrentPrefs().ControlURLOrDefault()
	if err := b.pm.SwitchProfile(profile); err != nil {
		return err
	}

	// As an optimization, only reset the dialPlan if the control URL
	// changed; we treat an empty URL as "unknown" and always reset.
	newControlURL := b.pm.CurrentPrefs().ControlURLOrDefault()
	if oldControlURL != newControlURL || oldControlURL == "" || newControlURL == "" {
		b.resetDialPlan()
	}

	return b.resetForProfileChangeLockedOnEntry(unlock)
}

func (b *LocalBackend) initTKALocked() error {

	return nil
}

// resetDialPlan resets the dialPlan for this LocalBackend. It will log if
// anything is reset.
//
// It is safe to call this concurrently, with or without b.mu held.
func (b *LocalBackend) resetDialPlan() {
	old := b.dialPlan.Swap(nil)
	if old != nil {
		b.logf("resetDialPlan: did reset")
	}
}

// resetForProfileChangeLockedOnEntry resets the backend for a profile change.
//
// b.mu must held on entry. It is released on exit.
func (b *LocalBackend) resetForProfileChangeLockedOnEntry(unlock unlockOnce) error {
	defer unlock()

	if b.shutdownCalled {
		// Prevent a call back to Start during Shutdown, which calls Logout for
		// ephemeral nodes, which can then call back here. But we're shutting
		// down, so no need to do any work.
		return nil
	}
	b.setNetMapLocked(nil) // Reset netmap.
	// Reset the NetworkMap in the engine
	b.e.SetNetworkMap(new(netmap.NetworkMap))
	if err := b.initTKALocked(); err != nil {
		return err
	}
	b.lastSuggestedExitNode = ""
	b.enterStateLockedOnEntry(ipn.NoState, unlock) // Reset state; releases b.mu
	b.health.SetLocalLogConfigHealth(nil)
	return b.Start(ipn.Options{})
}

// DeleteProfile deletes a profile with the given ID.
// If the profile is not known, it is a no-op.
func (b *LocalBackend) DeleteProfile(p ipn.ProfileID) error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	needToRestart := b.pm.CurrentProfile().ID == p
	if err := b.pm.DeleteProfile(p); err != nil {
		if err == errProfileNotFound {
			return nil
		}
		return err
	}
	if !needToRestart {
		return nil
	}
	return b.resetForProfileChangeLockedOnEntry(unlock)
}

// CurrentProfile returns the current LoginProfile.
// The value may be zero if the profile is not persisted.
func (b *LocalBackend) CurrentProfile() ipn.LoginProfile {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.CurrentProfile()
}

// NewProfile creates and switches to the new profile.
func (b *LocalBackend) NewProfile() error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	b.pm.NewProfile()

	// The new profile doesn't yet have a ControlURL because it hasn't been
	// set. Conservatively reset the dialPlan.
	b.resetDialPlan()

	return b.resetForProfileChangeLockedOnEntry(unlock)
}

// ListProfiles returns a list of all LoginProfiles.
func (b *LocalBackend) ListProfiles() []ipn.LoginProfile {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.Profiles()
}

// ResetAuth resets the authentication state, including persisted keys. Also
// has the side effect of removing all profiles and reseting preferences. The
// backend is left with a new profile, ready for StartLoginInterative to be
// called to register it as new node.
func (b *LocalBackend) ResetAuth() error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	prevCC := b.resetControlClientLocked()
	if prevCC != nil {
		defer prevCC.Shutdown() // call must happen after release b.mu
	}
	if err := b.clearMachineKeyLocked(); err != nil {
		return err
	}
	if err := b.pm.DeleteAllProfilesForUser(); err != nil {
		return err
	}
	b.resetDialPlan() // always reset if we're removing everything
	return b.resetForProfileChangeLockedOnEntry(unlock)
}

var breakTCPConns func() error

func (b *LocalBackend) DebugBreakTCPConns() error {
	if breakTCPConns == nil {
		return errors.New("TCP connection breaking not available on this platform")
	}
	return breakTCPConns()
}

func (b *LocalBackend) DebugBreakDERPConns() error {
	return b.MagicConn().DebugBreakDERPConns()
}

func (b *LocalBackend) pushSelfUpdateProgress(up ipnstate.UpdateProgress) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.selfUpdateProgress = append(b.selfUpdateProgress, up)
	b.lastSelfUpdateState = up.Status
}

func (b *LocalBackend) clearSelfUpdateProgress() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.selfUpdateProgress = make([]ipnstate.UpdateProgress, 0)
	b.lastSelfUpdateState = ipnstate.UpdateFinished
}

// ErrDisallowedAutoRoute is returned by AdvertiseRoute when a route that is not allowed is requested.
var ErrDisallowedAutoRoute = errors.New("route is not allowed")

// namespace a key with the profile manager's current profile key, if any
func namespaceKeyForCurrentProfile(pm *profileManager, key ipn.StateKey) ipn.StateKey {
	return pm.CurrentProfile().Key + "||" + key
}

const routeInfoStateStoreKey ipn.StateKey = "_routeInfo"

// seamlessRenewalEnabled reports whether seamless key renewals are enabled
// (i.e. we saw our self node with the SeamlessKeyRenewal attr in a netmap).
// This enables beta functionality of renewing node keys without breaking
// connections.
func (b *LocalBackend) seamlessRenewalEnabled() bool {
	return b.ControlKnobs().SeamlessKeyRenewal.Load()
}

var (
	disallowedAddrs = []netip.Addr{
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("0.0.0.0"),
	}
	disallowedRanges = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// allowedAutoRoute determines if the route being added via AdvertiseRoute (the app connector featuge) should be allowed.
func allowedAutoRoute(ipp netip.Prefix) bool {
	// Note: blocking the addrs for globals, not solely the prefixes.
	for _, addr := range disallowedAddrs {
		if ipp.Addr() == addr {
			return false
		}
	}
	for _, pfx := range disallowedRanges {
		if pfx.Overlaps(ipp) {
			return false
		}
	}
	// TODO(raggi): exclude tailscale service IPs and so on as well.
	return true
}

// mayDeref dereferences p if non-nil, otherwise it returns the zero value.
func mayDeref[T any](p *T) (v T) {
	if p == nil {
		return v
	}
	return *p
}

var ErrNoPreferredDERP = errors.New("no preferred DERP, try again later")

// suggestExitNodeLocked computes a suggestion based on the current netmap and last netcheck report. If
// there are multiple equally good options, one is selected at random, so the result is not stable. To be
// eligible for consideration, the peer must have NodeAttrSuggestExitNode in its CapMap.
//
// Currently, peers with a DERP home are preferred over those without (typically this means Mullvad).
// Peers are selected based on having a DERP home that is the lowest latency to this device. For peers
// without a DERP home, we look for geographic proximity to this device's DERP home.
//
// netMap is an optional netmap to use that overrides b.netMap (needed for SetControlClientStatus before b.netMap is updated).
// If netMap is nil, then b.netMap is used.
//
// b.mu.lock() must be held.
func (b *LocalBackend) suggestExitNodeLocked(netMap *netmap.NetworkMap) (response apitype.ExitNodeSuggestionResponse, err error) {
	// netMap is an optional netmap to use that overrides b.netMap (needed for SetControlClientStatus before b.netMap is updated). If netMap is nil, then b.netMap is used.
	if netMap == nil {
		netMap = b.netMap
	}
	lastReport := b.MagicConn().GetLastNetcheckReport(b.ctx)
	prevSuggestion := b.lastSuggestedExitNode

	res, err := suggestExitNode(lastReport, netMap, prevSuggestion, randomRegion, randomNode, b.getAllowedSuggestions())
	if err != nil {
		return res, err
	}
	b.lastSuggestedExitNode = res.ID
	return res, err
}

func (b *LocalBackend) SuggestExitNode() (response apitype.ExitNodeSuggestionResponse, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.suggestExitNodeLocked(nil)
}

// getAllowedSuggestions returns a set of exit nodes permitted by the most recent
// [syspolicy.AllowedSuggestedExitNodes] value. Callers must not mutate the returned set.
func (b *LocalBackend) getAllowedSuggestions() set.Set[tailcfg.StableNodeID] {
	b.allowedSuggestedExitNodesMu.Lock()
	defer b.allowedSuggestedExitNodesMu.Unlock()
	return b.allowedSuggestedExitNodes
}

// refreshAllowedSuggestions rebuilds the set of permitted exit nodes
// from the current [syspolicy.AllowedSuggestedExitNodes] value.
func (b *LocalBackend) refreshAllowedSuggestions() {
	b.allowedSuggestedExitNodesMu.Lock()
	defer b.allowedSuggestedExitNodesMu.Unlock()
	b.allowedSuggestedExitNodes = fillAllowedSuggestions()
}

// selectRegionFunc returns a DERP region from the slice of candidate regions.
// The value is returned, not the slice index.
type selectRegionFunc func(views.Slice[int]) int

// selectNodeFunc returns a node from the slice of candidate nodes. The last
// selected node is provided for when that information is needed to make a better
// choice.
type selectNodeFunc func(nodes views.Slice[tailcfg.NodeView], last tailcfg.StableNodeID) tailcfg.NodeView

func fillAllowedSuggestions() set.Set[tailcfg.StableNodeID] {
	nodes, err := syspolicy.GetStringArray(syspolicy.AllowedSuggestedExitNodes, nil)
	if err != nil {
		log.Printf("fillAllowedSuggestions: unable to look up %q policy: %v", syspolicy.AllowedSuggestedExitNodes, err)
		return nil
	}
	if nodes == nil {
		return nil
	}
	s := make(set.Set[tailcfg.StableNodeID], len(nodes))
	for _, n := range nodes {
		s.Add(tailcfg.StableNodeID(n))
	}
	return s
}

func suggestExitNode(report *netcheck.Report, netMap *netmap.NetworkMap, prevSuggestion tailcfg.StableNodeID, selectRegion selectRegionFunc, selectNode selectNodeFunc, allowList set.Set[tailcfg.StableNodeID]) (res apitype.ExitNodeSuggestionResponse, err error) {
	if report == nil || report.PreferredDERP == 0 || netMap == nil || netMap.DERPMap == nil {
		return res, ErrNoPreferredDERP
	}
	candidates := make([]tailcfg.NodeView, 0, len(netMap.Peers))
	for _, peer := range netMap.Peers {
		if !peer.Valid() {
			continue
		}
		if allowList != nil && !allowList.Contains(peer.StableID()) {
			continue
		}
		if peer.CapMap().Contains(tailcfg.NodeAttrSuggestExitNode) && tsaddr.ContainsExitRoutes(peer.AllowedIPs()) {
			candidates = append(candidates, peer)
		}
	}
	if len(candidates) == 0 {
		return res, nil
	}
	if len(candidates) == 1 {
		peer := candidates[0]
		if hi := peer.Hostinfo(); hi.Valid() {
			if loc := hi.Location(); loc != nil {
				res.Location = loc.View()
			}
		}
		res.ID = peer.StableID()
		res.Name = peer.Name()
		return res, nil
	}

	candidatesByRegion := make(map[int][]tailcfg.NodeView, len(netMap.DERPMap.Regions))
	preferredDERP, ok := netMap.DERPMap.Regions[report.PreferredDERP]
	if !ok {
		return res, ErrNoPreferredDERP
	}
	var minDistance float64 = math.MaxFloat64
	type nodeDistance struct {
		nv       tailcfg.NodeView
		distance float64 // in meters, approximately
	}
	distances := make([]nodeDistance, 0, len(candidates))
	for _, c := range candidates {
		if c.DERP() != "" {
			ipp, err := netip.ParseAddrPort(c.DERP())
			if err != nil {
				continue
			}
			if ipp.Addr() != tailcfg.DerpMagicIPAddr {
				continue
			}
			regionID := int(ipp.Port())
			candidatesByRegion[regionID] = append(candidatesByRegion[regionID], c)
			continue
		}
		if len(candidatesByRegion) > 0 {
			// Since a candidate exists that does have a DERP home, skip this candidate. We never select
			// a candidate without a DERP home if there is a candidate available with a DERP home.
			continue
		}
		// This candidate does not have a DERP home.
		// Use geographic distance from our DERP home to estimate how good this candidate is.
		hi := c.Hostinfo()
		if !hi.Valid() {
			continue
		}
		loc := hi.Location()
		if loc == nil {
			continue
		}
		distance := longLatDistance(preferredDERP.Latitude, preferredDERP.Longitude, loc.Latitude, loc.Longitude)
		if distance < minDistance {
			minDistance = distance
		}
		distances = append(distances, nodeDistance{nv: c, distance: distance})
	}
	// First, try to select an exit node that has the closest DERP home, based on lastReport's DERP latency.
	// If there are no latency values, it returns an arbitrary region
	if len(candidatesByRegion) > 0 {
		minRegion := minLatencyDERPRegion(slicesx.MapKeys(candidatesByRegion), report)
		if minRegion == 0 {
			minRegion = selectRegion(views.SliceOf(slicesx.MapKeys(candidatesByRegion)))
		}
		regionCandidates, ok := candidatesByRegion[minRegion]
		if !ok {
			return res, errors.New("no candidates in expected region: this is a bug")
		}
		chosen := selectNode(views.SliceOf(regionCandidates), prevSuggestion)
		res.ID = chosen.StableID()
		res.Name = chosen.Name()
		if hi := chosen.Hostinfo(); hi.Valid() {
			if loc := hi.Location(); loc != nil {
				res.Location = loc.View()
			}
		}
		return res, nil
	}
	// None of the candidates have a DERP home, so proceed to select based on geographical distance from our preferred DERP region.

	// allowanceMeters is the extra distance that will be permitted when considering peers. By this point, there
	// are multiple approximations taking place (DERP location standing in for this device's location, the peer's
	// location may only be city granularity, the distance algorithm assumes a spherical planet, etc.) so it is
	// reasonable to consider peers that are similar distances. Those peers are good enough to be within
	// measurement error. 100km corresponds to approximately 1ms of additional round trip light
	// propagation delay in a fiber optic cable and seems like a reasonable heuristic. It may be adjusted in
	// future.
	const allowanceMeters = 100000
	pickFrom := make([]tailcfg.NodeView, 0, len(distances))
	for _, candidate := range distances {
		if candidate.nv.Valid() && candidate.distance <= minDistance+allowanceMeters {
			pickFrom = append(pickFrom, candidate.nv)
		}
	}
	bestCandidates := pickWeighted(pickFrom)
	chosen := selectNode(views.SliceOf(bestCandidates), prevSuggestion)
	if !chosen.Valid() {
		return res, errors.New("chosen candidate invalid: this is a bug")
	}
	res.ID = chosen.StableID()
	res.Name = chosen.Name()
	if hi := chosen.Hostinfo(); hi.Valid() {
		if loc := hi.Location(); loc != nil {
			res.Location = loc.View()
		}
	}
	return res, nil
}

// pickWeighted chooses the node with highest priority given a list of mullvad nodes.
func pickWeighted(candidates []tailcfg.NodeView) []tailcfg.NodeView {
	maxWeight := 0
	best := make([]tailcfg.NodeView, 0, 1)
	for _, c := range candidates {
		hi := c.Hostinfo()
		if !hi.Valid() {
			continue
		}
		loc := hi.Location()
		if loc == nil || loc.Priority < maxWeight {
			continue
		}
		if maxWeight != loc.Priority {
			best = best[:0]
		}
		maxWeight = loc.Priority
		best = append(best, c)
	}
	return best
}

// randomRegion is a selectRegionFunc that selects a uniformly random region.
func randomRegion(regions views.Slice[int]) int {
	return regions.At(rand.IntN(regions.Len()))
}

// randomNode is a selectNodeFunc that will return the node matching prefer if
// present, otherwise a uniformly random node will be selected.
func randomNode(nodes views.Slice[tailcfg.NodeView], prefer tailcfg.StableNodeID) tailcfg.NodeView {
	if !prefer.IsZero() {
		for i := range nodes.Len() {
			nv := nodes.At(i)
			if nv.StableID() == prefer {
				return nv
			}
		}
	}

	return nodes.At(rand.IntN(nodes.Len()))
}

// minLatencyDERPRegion returns the region with the lowest latency value given the last netcheck report.
// If there are no latency values, it returns 0.
func minLatencyDERPRegion(regions []int, report *netcheck.Report) int {
	min := slices.MinFunc(regions, func(i, j int) int {
		const largeDuration time.Duration = math.MaxInt64
		iLatency, ok := report.RegionLatency[i]
		if !ok {
			iLatency = largeDuration
		}
		jLatency, ok := report.RegionLatency[j]
		if !ok {
			jLatency = largeDuration
		}
		if c := cmp.Compare(iLatency, jLatency); c != 0 {
			return c
		}
		return cmp.Compare(i, j)
	})
	latency, ok := report.RegionLatency[min]
	if !ok || latency == 0 {
		return 0
	} else {
		return min
	}
}

// longLatDistance returns an estimated distance given the geographic coordinates of two locations, in degrees.
// The coordinates are separated into four separate float64 values.
// Value is returned in meters.
func longLatDistance(fromLat, fromLong, toLat, toLong float64) float64 {
	const toRadians = math.Pi / 180
	diffLat := (fromLat - toLat) * toRadians
	diffLong := (fromLong - toLong) * toRadians
	lat1 := fromLat * toRadians
	lat2 := toLat * toRadians
	a := math.Pow(math.Sin(diffLat/2), 2) + math.Cos(lat1)*math.Cos(lat2)*math.Pow(math.Sin(diffLong/2), 2)
	const earthRadiusMeters = 6371000
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusMeters * c
}

// shouldAutoExitNode checks for the auto exit node MDM policy.
func shouldAutoExitNode() bool {
	exitNodeIDStr, _ := syspolicy.GetString(syspolicy.ExitNodeID, "")
	return exitNodeIDStr == "auto:any"
}

// srcIPHasCapForFilter is called by the packet filter when evaluating firewall
// rules that require a source IP to have a certain node capability.
//
// TODO(bradfitz): optimize this later if/when it matters.
func (b *LocalBackend) srcIPHasCapForFilter(srcIP netip.Addr, cap tailcfg.NodeCapability) bool {
	if cap == "" {
		// Shouldn't happen, but just in case.
		// But the empty cap also shouldn't be found in Node.CapMap.
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	nodeID, ok := b.nodeByAddr[srcIP]
	if !ok {
		return false
	}
	n, ok := b.peers[nodeID]
	if !ok {
		return false
	}
	return n.HasCap(cap)
}

// maybeUsernameOf returns the actor's username if the actor
// is non-nil and its username can be resolved.
func maybeUsernameOf(actor ipnauth.Actor) string {
	var username string
	if actor != nil {
		username, _ = actor.Username()
	}
	return username
}

// VIPServices returns the list of tailnet services that this node
// is serving as a destination for.
// The returned memory is owned by the caller.
func (b *LocalBackend) VIPServices() []*tailcfg.VIPService {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.vipServicesFromPrefsLocked(b.pm.CurrentPrefs())
}

func (b *LocalBackend) vipServiceHash(services []*tailcfg.VIPService) string {
	if len(services) == 0 {
		return ""
	}
	buf, err := json.Marshal(services)
	if err != nil {
		b.logf("vipServiceHashLocked: %v", err)
		return ""
	}
	hash := sha256.Sum256(buf)
	return hex.EncodeToString(hash[:])
}

func (b *LocalBackend) vipServicesFromPrefsLocked(prefs ipn.PrefsView) []*tailcfg.VIPService {
	return nil
}

var (
	metricCurrentWatchIPNBus = clientmetric.NewGauge("localbackend_current_watch_ipn_bus")
)
