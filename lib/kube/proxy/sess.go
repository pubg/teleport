/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/kube/proxy/streamproto"
	tsession "github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/remotecommand"
)

const sessionRecorderID = "session-recorder"

const PresenceVerifyInterval = time.Second * 15
const PresenceMaxDifference = time.Minute
const sessionMaxLifetime = time.Hour * 24

// remoteClient is either a kubectl or websocket client.
type remoteClient interface {
	stdinStream() io.Reader
	stdoutStream() io.Writer
	stderrStream() io.Writer
	resizeQueue() <-chan *remotecommand.TerminalSize
	resize(size *remotecommand.TerminalSize) error
	forceTerminate() <-chan struct{}
	sendStatus(error) error
	io.Closer
}

type websocketClientStreams struct {
	stream *streamproto.SessionStream
}

func (p *websocketClientStreams) stdinStream() io.Reader {
	return p.stream
}

func (p *websocketClientStreams) stdoutStream() io.Writer {
	return p.stream
}

func (p *websocketClientStreams) stderrStream() io.Writer {
	return p.stream
}

func (p *websocketClientStreams) resizeQueue() <-chan *remotecommand.TerminalSize {
	return p.stream.ResizeQueue()
}

func (p *websocketClientStreams) resize(size *remotecommand.TerminalSize) error {
	return p.stream.Resize(size)
}

func (p *websocketClientStreams) forceTerminate() <-chan struct{} {
	return p.stream.ForceTerminateQueue()
}

func (p *websocketClientStreams) sendStatus(err error) error {
	return nil
}

func (p *websocketClientStreams) Close() error {
	return trace.Wrap(p.stream.Close())
}

type kubeProxyClientStreams struct {
	proxy     *remoteCommandProxy
	sizeQueue remotecommand.TerminalSizeQueue
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	close     chan struct{}
}

func newKubeProxyClientStreams(proxy *remoteCommandProxy) *kubeProxyClientStreams {
	options := proxy.options()

	return &kubeProxyClientStreams{
		proxy:     proxy,
		stdin:     options.Stdin,
		stdout:    options.Stdout,
		stderr:    options.Stderr,
		close:     make(chan struct{}),
		sizeQueue: proxy.resizeQueue,
	}
}

func (p *kubeProxyClientStreams) stdinStream() io.Reader {
	return p.stdin
}

func (p *kubeProxyClientStreams) stdoutStream() io.Writer {
	return p.stdout
}

func (p *kubeProxyClientStreams) stderrStream() io.Writer {
	return p.stderr
}

func (p *kubeProxyClientStreams) resizeQueue() <-chan *remotecommand.TerminalSize {
	ch := make(chan *remotecommand.TerminalSize)
	go func() {
		for {
			size := p.sizeQueue.Next()
			if size == nil {
				break
			}

			ch <- size
		}
	}()

	return ch
}

func (p *kubeProxyClientStreams) resize(size *remotecommand.TerminalSize) error {
	escape := fmt.Sprintf("\x1b[8;%d;%dt", size.Height, size.Width)
	_, err := p.stdout.Write([]byte(escape))
	return trace.Wrap(err)
}

func (p *kubeProxyClientStreams) forceTerminate() <-chan struct{} {
	return make(chan struct{})
}

func (p *kubeProxyClientStreams) sendStatus(err error) error {
	return trace.Wrap(p.proxy.sendStatus(err))
}

func (p *kubeProxyClientStreams) Close() error {
	close(p.close)
	return trace.Wrap(p.proxy.Close())
}

// multiResizeQueue is a merged queue of multiple terminal size queues.
type multiResizeQueue struct {
	queues   map[string]<-chan *remotecommand.TerminalSize
	cases    []reflect.SelectCase
	callback func(*remotecommand.TerminalSize)
}

func newMultiResizeQueue() *multiResizeQueue {
	return &multiResizeQueue{
		queues: make(map[string]<-chan *remotecommand.TerminalSize),
	}
}

func (r *multiResizeQueue) rebuild() {
	r.cases = nil
	for _, queue := range r.queues {
		r.cases = append(r.cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(queue),
		})
	}
}

func (r *multiResizeQueue) add(id string, queue <-chan *remotecommand.TerminalSize) {
	r.queues[id] = queue
	r.rebuild()
}

func (r *multiResizeQueue) remove(id string) {
	delete(r.queues, id)
	r.rebuild()
}

func (r *multiResizeQueue) Next() *remotecommand.TerminalSize {
	_, value, ok := reflect.Select(r.cases)
	if !ok {
		return nil
	}

	size := value.Interface().(*remotecommand.TerminalSize)
	r.callback(size)
	return size
}

// party represents one participant of the session and their associated state.
type party struct {
	Ctx       authContext
	ID        uuid.UUID
	Client    remoteClient
	Mode      types.SessionParticipantMode
	closeC    chan struct{}
	closeOnce sync.Once
}

// newParty creates a new party.
func newParty(ctx authContext, mode types.SessionParticipantMode, client remoteClient) *party {
	return &party{
		Ctx:    ctx,
		ID:     uuid.New(),
		Client: client,
		Mode:   mode,
		closeC: make(chan struct{}),
	}
}

// Close closes the party and disconnects the remote end.
func (p *party) Close() error {
	var err error

	p.closeOnce.Do(func() {
		close(p.closeC)
		err = p.Client.Close()
	})

	return trace.Wrap(err)
}

// session represents an ongoing k8s session.
type session struct {
	mu sync.RWMutex

	// ctx is the auth context of the session initiator
	ctx authContext

	forwarder *Forwarder

	req *http.Request

	params httprouter.Params

	id uuid.UUID

	// parties is a map of currently active parties.
	parties map[uuid.UUID]*party

	// partiesHistorical is a map of all current previous parties.
	// This is used for audit trails.
	partiesHistorical map[uuid.UUID]*party

	log *log.Entry

	io *srv.TermManager

	terminalSizeQueue *multiResizeQueue

	state types.SessionState

	// stateUpdate is used to notify listeners about state updates
	stateUpdate *sync.Cond

	accessEvaluator auth.SessionAccessEvaluator

	recorder events.StreamWriter

	emitter apievents.Emitter

	podName string

	started bool

	initiator uuid.UUID

	expires time.Time

	// sess is the clusterSession used to establish this session.
	sess *clusterSession

	closeC chan struct{}

	closeOnce sync.Once

	// PresenceEnabled is set to true if MFA based presence is required.
	PresenceEnabled bool

	// Set if we should broadcast information about participant requirements to the session.
	displayParticipantRequirements bool
}

// newSession creates a new session in pending mode.
func newSession(ctx authContext, forwarder *Forwarder, req *http.Request, params httprouter.Params, initiator *party, sess *clusterSession) (*session, error) {
	id := uuid.New()
	log := forwarder.log.WithField("session", id.String())
	log.Debug("Creating session")
	roles, err := getRolesByName(forwarder, ctx.Context.Identity.GetIdentity().Groups)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var policySets []*types.SessionTrackerPolicySet
	for _, role := range roles {
		policySet := role.GetSessionPolicySet()
		policySets = append(policySets, &policySet)
	}

	q := req.URL.Query()
	accessEvaluator := auth.NewSessionAccessEvaluator(policySets, types.KubernetesSessionKind)

	io := srv.NewTermManager()

	s := &session{
		ctx:                            ctx,
		forwarder:                      forwarder,
		req:                            req,
		params:                         params,
		id:                             id,
		parties:                        make(map[uuid.UUID]*party),
		partiesHistorical:              make(map[uuid.UUID]*party),
		log:                            log,
		io:                             io,
		state:                          types.SessionState_SessionStatePending,
		accessEvaluator:                accessEvaluator,
		emitter:                        events.NewDiscardEmitter(),
		terminalSizeQueue:              newMultiResizeQueue(),
		started:                        false,
		sess:                           sess,
		closeC:                         make(chan struct{}),
		initiator:                      initiator.ID,
		expires:                        time.Now().UTC().Add(sessionMaxLifetime),
		PresenceEnabled:                ctx.Identity.GetIdentity().MFAVerified != "",
		stateUpdate:                    sync.NewCond(&sync.Mutex{}),
		displayParticipantRequirements: utils.AsBool(q.Get("displayParticipantRequirements")),
	}

	s.BroadcastMessage("Creating session with ID: %v...", id.String())
	s.BroadcastMessage(srv.SessionControlsInfoBroadcast)

	go func() {
		if _, open := <-s.io.TerminateNotifier(); open {
			err := s.Close()
			if err != nil {
				s.log.Errorf("Failed to close session: %v.", err)
			}
		}
	}()

	err = s.trackerCreate(initiator, policySets)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return s, nil
}

// waitOnAccess puts the session in pending mode and waits for the session
// to fulfill the access requirements again.
func (s *session) waitOnAccess() {
	s.io.Off()
	s.BroadcastMessage("Session paused, Waiting for required participants...")

	s.stateUpdate.L.Lock()
	defer s.stateUpdate.L.Unlock()

outer:
	for {
		switch s.state {
		case types.SessionState_SessionStatePending:
			continue
		case types.SessionState_SessionStateTerminated:
			return
		case types.SessionState_SessionStateRunning:
			break outer
		}

		s.stateUpdate.Wait()
	}

	s.BroadcastMessage("Resuming session...")
	s.io.On()
}

// checkPresence checks the presence timestamp of involved moderators
// and kicks them if they are not active.
func (s *session) checkPresence() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.trackerGet()
	if err != nil {
		return trace.Wrap(err)
	}

	for _, participant := range sess.GetParticipants() {
		if participant.ID == s.initiator.String() {
			continue
		}

		if participant.Mode == string(types.SessionModeratorMode) && time.Now().UTC().After(participant.LastActive.Add(PresenceMaxDifference)) {
			s.log.Debugf("Participant %v is not active, kicking.", participant.ID)
			id, _ := uuid.Parse(participant.ID)
			err := s.leave(id)
			if err != nil {
				s.log.WithError(err).Warnf("Failed to kick participant %v for inactivity.", participant.ID)
			}
		}
	}

	return nil
}

// launch waits until the session meets access requirements and then transitions the session
// to a running state.
func (s *session) launch() error {
	defer func() {
		err := s.Close()
		if err != nil {
			s.log.WithError(err).Errorf("Failed to close session: %v", s.id)
		}
	}()

	s.log.Debugf("Launching session: %v", s.id)

	q := s.req.URL.Query()
	request := &remoteCommandRequest{
		podNamespace:       s.params.ByName("podNamespace"),
		podName:            s.params.ByName("podName"),
		containerName:      q.Get("container"),
		cmd:                q["command"],
		stdin:              utils.AsBool(q.Get("stdin")),
		stdout:             utils.AsBool(q.Get("stdout")),
		stderr:             utils.AsBool(q.Get("stderr")),
		httpRequest:        s.req,
		httpResponseWriter: nil,
		context:            s.req.Context(),
		pingPeriod:         s.forwarder.cfg.ConnPingPeriod,
	}

	s.podName = request.podName
	s.BroadcastMessage("Connecting to %v over K8S", s.podName)

	eventPodMeta := request.eventPodMeta(request.context, s.sess.creds)
	s.io.OnWriteError = func(idString string, err error) {
		s.mu.Lock()
		defer s.mu.Unlock()

		if idString == sessionRecorderID {
			s.log.Error("Failed to write to session recorder, closing session.")
			s.Close()
		}

		s.log.Errorf("Encountered error: %v with party %v. Disconnecting them from the session.", err, idString)
		id, _ := uuid.Parse(idString)
		if s.parties[id] != nil {
			err = s.leave(id)
			if err != nil {
				s.log.Errorf("Failed to disconnect party %v from the session: %v.", idString, err)
			}
		}
	}

	onFinished, err := s.lockedSetupLaunch(request, q, eventPodMeta)
	if err != nil {
		return trace.Wrap(err)
	}

	termParams := tsession.TerminalParams{
		W: 100,
		H: 100,
	}

	sessionStartEvent := &apievents.SessionStart{
		Metadata: apievents.Metadata{
			Type:        events.SessionStartEvent,
			Code:        events.SessionStartCode,
			ClusterName: s.forwarder.cfg.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        s.forwarder.cfg.ServerID,
			ServerNamespace: s.forwarder.cfg.Namespace,
			ServerHostname:  s.sess.teleportCluster.name,
			ServerAddr:      s.sess.kubeAddress,
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: s.id.String(),
			WithMFA:   s.ctx.Identity.GetIdentity().MFAVerified,
		},
		UserMetadata: apievents.UserMetadata{
			User:         s.ctx.User.GetName(),
			Login:        s.ctx.User.GetName(),
			Impersonator: s.ctx.Identity.GetIdentity().Impersonator,
		},
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: s.req.RemoteAddr,
			LocalAddr:  s.sess.kubeAddress,
			Protocol:   events.EventProtocolKube,
		},
		TerminalSize:              termParams.Serialize(),
		KubernetesClusterMetadata: s.ctx.eventClusterMeta(),
		KubernetesPodMetadata:     eventPodMeta,
		InitialCommand:            q["command"],
		SessionRecording:          s.ctx.recordingConfig.GetMode(),
	}

	if err := s.emitter.EmitAuditEvent(s.forwarder.ctx, sessionStartEvent); err != nil {
		s.forwarder.log.WithError(err).Warn("Failed to emit event.")
	}

	go func() {
		select {
		case <-time.After(time.Until(s.expires)):
			s.mu.Lock()
			defer s.mu.Unlock()
			s.BroadcastMessage("Session expired, closing...")

			err := s.Close()
			if err != nil {
				s.log.WithError(err).Error("Failed to close session")
			}
		case <-s.closeC:
		}
	}()

	err = s.trackerUpdateState(types.SessionState_SessionStateRunning)
	if err != nil {
		s.log.Warn("Failed to set tracker state to running")
	}

	defer onFinished()
	executor, err := s.forwarder.getExecutor(s.ctx, s.sess, s.req)
	if err != nil {
		s.log.WithError(err).Warning("Failed creating executor.")
		return trace.Wrap(err)
	}

	options := remotecommand.StreamOptions{
		Stdin:             s.io,
		Stdout:            s.io,
		Stderr:            s.io,
		Tty:               true,
		TerminalSizeQueue: s.terminalSizeQueue,
	}

	s.io.On()
	if err = executor.Stream(options); err != nil {
		s.log.WithError(err).Warning("Executor failed while streaming.")
		return trace.Wrap(err)
	}

	return nil
}

func (s *session) lockedSetupLaunch(request *remoteCommandRequest, q url.Values, eventPodMeta apievents.KubernetesPodMetadata) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	s.started = true
	sessionStart := s.forwarder.cfg.Clock.Now().UTC()

	if !s.sess.noAuditEvents {
		s.terminalSizeQueue.callback = func(resize *remotecommand.TerminalSize) {
			s.mu.Lock()
			defer s.mu.Unlock()

			for id, p := range s.parties {
				err := p.Client.resize(resize)
				if err != nil {
					s.log.WithError(err).Errorf("Failed to resize client: %v", id.String())
				}
			}

			params := tsession.TerminalParams{
				W: int(resize.Width),
				H: int(resize.Height),
			}

			resizeEvent := &apievents.Resize{
				Metadata: apievents.Metadata{
					Type:        events.ResizeEvent,
					Code:        events.TerminalResizeCode,
					ClusterName: s.forwarder.cfg.ClusterName,
				},
				ConnectionMetadata: apievents.ConnectionMetadata{
					RemoteAddr: s.req.RemoteAddr,
					Protocol:   events.EventProtocolKube,
				},
				ServerMetadata: apievents.ServerMetadata{
					ServerNamespace: s.forwarder.cfg.Namespace,
				},
				SessionMetadata: apievents.SessionMetadata{
					SessionID: s.id.String(),
					WithMFA:   s.ctx.Identity.GetIdentity().MFAVerified,
				},
				UserMetadata: apievents.UserMetadata{
					User:         s.ctx.User.GetName(),
					Login:        s.ctx.User.GetName(),
					Impersonator: s.ctx.Identity.GetIdentity().Impersonator,
				},
				TerminalSize:              params.Serialize(),
				KubernetesClusterMetadata: s.ctx.eventClusterMeta(),
				KubernetesPodMetadata:     eventPodMeta,
			}

			// Report the updated window size to the event log (this is so the sessions
			// can be replayed correctly).
			if err := s.recorder.EmitAuditEvent(s.forwarder.ctx, resizeEvent); err != nil {
				s.forwarder.log.WithError(err).Warn("Failed to emit terminal resize event.")
			}
		}
	} else {
		s.terminalSizeQueue.callback = func(resize *remotecommand.TerminalSize) {}
	}

	streamer, err := s.forwarder.newStreamer(&s.ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	recorder, err := events.NewAuditWriter(events.AuditWriterConfig{
		// Audit stream is using server context, not session context,
		// to make sure that session is uploaded even after it is closed
		Context:      s.forwarder.ctx,
		Streamer:     streamer,
		Clock:        s.forwarder.cfg.Clock,
		SessionID:    tsession.ID(s.id.String()),
		ServerID:     s.forwarder.cfg.ServerID,
		Namespace:    s.forwarder.cfg.Namespace,
		RecordOutput: s.ctx.recordingConfig.GetMode() != types.RecordOff,
		Component:    teleport.Component(teleport.ComponentSession, teleport.ComponentProxyKube),
		ClusterName:  s.forwarder.cfg.ClusterName,
	})

	s.recorder = recorder
	s.emitter = recorder
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s.io.AddWriter(sessionRecorderID, recorder)

	// If the identity is verified with an MFA device, we enabled MFA-based presence for the session.
	if s.PresenceEnabled {
		go func() {
			ticker := time.NewTicker(PresenceVerifyInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					err := s.checkPresence()
					if err != nil {
						s.log.WithError(err).Error("Failed to check presence, closing session as a security measure")
						err := s.Close()
						if err != nil {
							s.log.WithError(err).Error("Failed to close session")
						}
					}
				case <-s.closeC:
					return
				}
			}
		}()
	}

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		for _, party := range s.parties {
			if err := party.Client.sendStatus(err); err != nil {
				s.forwarder.log.WithError(err).Warning("Failed to send status. Exec command was aborted by client.")
			}
		}

		sessionDataEvent := &apievents.SessionData{
			Metadata: apievents.Metadata{
				Type:        events.SessionDataEvent,
				Code:        events.SessionDataCode,
				ClusterName: s.forwarder.cfg.ClusterName,
			},
			ServerMetadata: apievents.ServerMetadata{
				ServerID:        s.forwarder.cfg.ServerID,
				ServerNamespace: s.forwarder.cfg.Namespace,
			},
			SessionMetadata: apievents.SessionMetadata{
				SessionID: s.id.String(),
				WithMFA:   s.ctx.Identity.GetIdentity().MFAVerified,
			},
			UserMetadata: apievents.UserMetadata{
				User:         s.ctx.User.GetName(),
				Login:        s.ctx.User.GetName(),
				Impersonator: s.ctx.Identity.GetIdentity().Impersonator,
			},
			ConnectionMetadata: apievents.ConnectionMetadata{
				RemoteAddr: s.req.RemoteAddr,
				LocalAddr:  s.sess.kubeAddress,
				Protocol:   events.EventProtocolKube,
			},
			// Bytes transmitted from user to pod.
			BytesTransmitted: s.io.CountRead(),
			// Bytes received from pod by user.
			BytesReceived: s.io.CountWritten(),
		}

		if err := s.emitter.EmitAuditEvent(s.forwarder.ctx, sessionDataEvent); err != nil {
			s.forwarder.log.WithError(err).Warn("Failed to emit session data event.")
		}

		sessionEndEvent := &apievents.SessionEnd{
			Metadata: apievents.Metadata{
				Type:        events.SessionEndEvent,
				Code:        events.SessionEndCode,
				ClusterName: s.forwarder.cfg.ClusterName,
			},
			ServerMetadata: apievents.ServerMetadata{
				ServerID:        s.forwarder.cfg.ServerID,
				ServerNamespace: s.forwarder.cfg.Namespace,
			},
			SessionMetadata: apievents.SessionMetadata{
				SessionID: s.id.String(),
				WithMFA:   s.ctx.Identity.GetIdentity().MFAVerified,
			},
			UserMetadata: apievents.UserMetadata{
				User:         s.ctx.User.GetName(),
				Login:        s.ctx.User.GetName(),
				Impersonator: s.ctx.Identity.GetIdentity().Impersonator,
			},
			ConnectionMetadata: apievents.ConnectionMetadata{
				RemoteAddr: s.req.RemoteAddr,
				LocalAddr:  s.sess.kubeAddress,
				Protocol:   events.EventProtocolKube,
			},
			Interactive:               true,
			Participants:              s.allParticipants(),
			StartTime:                 sessionStart,
			EndTime:                   s.forwarder.cfg.Clock.Now().UTC(),
			KubernetesClusterMetadata: s.ctx.eventClusterMeta(),
			KubernetesPodMetadata:     eventPodMeta,
			InitialCommand:            request.cmd,
			SessionRecording:          s.ctx.recordingConfig.GetMode(),
		}

		if err := s.emitter.EmitAuditEvent(s.forwarder.ctx, sessionEndEvent); err != nil {
			s.forwarder.log.WithError(err).Warn("Failed to emit session end event.")
		}
	}, nil
}

// join attempts to connect a party to the session.
func (s *session) join(p *party) error {
	if p.Ctx.User.GetName() != s.ctx.User.GetName() {
		roleNames := p.Ctx.Identity.GetIdentity().Groups
		roles, err := getRolesByName(s.forwarder, roleNames)
		if err != nil {
			return trace.Wrap(err)
		}

		accessContext := auth.SessionAccessContext{
			Username: p.Ctx.User.GetName(),
			Roles:    roles,
		}

		modes, err := s.accessEvaluator.CanJoin(accessContext)
		if err != nil {
			return trace.Wrap(err)
		}

		if !auth.SliceContainsMode(modes, p.Mode) {
			return trace.AccessDenied("insufficient permissions to join session")
		}
	}

	s.stateUpdate.L.Lock()
	state := s.state
	s.stateUpdate.L.Unlock()

	if state == types.SessionState_SessionStateTerminated {
		return trace.AccessDenied("The requested session is not active")
	}

	err := s.trackerAddParticipant(p)
	if err != nil {
		return trace.Wrap(err)
	}

	sessionJoinEvent := &apievents.SessionJoin{
		Metadata: apievents.Metadata{
			Type:        events.SessionJoinEvent,
			Code:        events.SessionJoinCode,
			ClusterName: s.ctx.teleportCluster.name,
		},
		KubernetesClusterMetadata: apievents.KubernetesClusterMetadata{
			KubernetesCluster: s.ctx.kubeCluster,
			KubernetesUsers:   []string{},
			KubernetesGroups:  []string{},
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: s.id.String(),
		},
		UserMetadata: apievents.UserMetadata{
			User:         p.Ctx.User.GetName(),
			Login:        "root",
			Impersonator: p.Ctx.Identity.GetIdentity().Impersonator,
		},
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: s.params.ByName("podName"),
		},
	}

	if err := s.emitter.EmitAuditEvent(s.forwarder.ctx, sessionJoinEvent); err != nil {
		s.forwarder.log.WithError(err).Warn("Failed to emit event.")
	}

	recentWrites := s.io.GetRecentHistory()
	_, err = p.Client.stdoutStream().Write(recentWrites)
	if err != nil {
		s.log.Warnf("Failed to write history to client: %v.", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	stringID := p.ID.String()
	s.parties[p.ID] = p
	s.partiesHistorical[p.ID] = p
	s.terminalSizeQueue.add(stringID, p.Client.resizeQueue())

	if p.Mode == types.SessionPeerMode {
		s.io.AddReader(stringID, p.Client.stdinStream())
	}

	s.io.AddWriter(stringID, p.Client.stdoutStream())
	s.BroadcastMessage("User %v joined the session.", p.Ctx.User.GetName())

	if p.Mode == types.SessionModeratorMode {
		go func() {
			c := p.Client.forceTerminate()
			select {
			case <-c:
				go func() {
					s.log.Debugf("Received force termination request")
					err := s.Close()
					if err != nil {
						s.log.Errorf("Failed to close session: %v.", err)
					}
				}()
			case <-s.closeC:
				return
			}
		}()
	}

	if !s.started {
		canStart, _, err := s.canStart()
		if err != nil {
			return trace.Wrap(err)
		}

		if canStart {
			go func() {
				if err := s.launch(); err != nil {
					s.log.WithError(err).Warning("Failed to launch Kubernetes session.")
				}
			}()
		} else if len(s.parties) == 1 {
			base := "Waiting for required participants..."

			if s.displayParticipantRequirements {
				s.BroadcastMessage(base+"\r\n%v", s.accessEvaluator.PrettyRequirementsList())
			} else {
				s.BroadcastMessage(base)
			}
		}
	}

	return nil
}

func (s *session) BroadcastMessage(format string, args ...interface{}) {
	if s.accessEvaluator.IsModerated() {
		s.io.BroadcastMessage(fmt.Sprintf(format, args...))
	}
}

// leave removes a party from the session.
func (s *session) leave(id uuid.UUID) error {
	s.stateUpdate.L.Lock()
	defer s.stateUpdate.L.Unlock()

	if s.state == types.SessionState_SessionStateTerminated {
		return nil
	}

	stringID := id.String()
	party := s.parties[id]

	if party == nil {
		return nil
	}

	delete(s.parties, id)
	s.terminalSizeQueue.remove(stringID)
	s.io.DeleteReader(stringID)
	s.io.DeleteWriter(stringID)

	s.BroadcastMessage("User %v left the session.", party.Ctx.User.GetName())

	sessionLeaveEvent := &apievents.SessionLeave{
		Metadata: apievents.Metadata{
			Type:        events.SessionJoinEvent,
			Code:        events.SessionJoinCode,
			ClusterName: s.ctx.teleportCluster.name,
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: s.id.String(),
		},
		UserMetadata: apievents.UserMetadata{
			User:         party.Ctx.User.GetName(),
			Login:        "root",
			Impersonator: party.Ctx.Identity.GetIdentity().Impersonator,
		},
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: s.params.ByName("podName"),
		},
	}

	if err := s.emitter.EmitAuditEvent(s.forwarder.ctx, sessionLeaveEvent); err != nil {
		s.forwarder.log.WithError(err).Warn("Failed to emit event.")
	}

	err := s.trackerRemoveParticipant(party.ID.String())
	if err != nil {
		return trace.Wrap(err)
	}

	err = party.Close()
	if err != nil {
		s.log.WithError(err).Error("Error closing party")
		return trace.Wrap(err)
	}

	if len(s.parties) == 0 || id == s.initiator {
		go func() {
			err := s.Close()
			if err != nil {
				s.log.WithError(err).Errorf("Failed to close session")
			}
		}()

		return nil
	}

	canStart, options, err := s.canStart()
	if err != nil {
		return trace.Wrap(err)
	}

	if !canStart {
		if options.TerminateOnLeave {
			go func() {
				err := s.Close()
				if err != nil {
					s.log.WithError(err).Errorf("Failed to close session")
				}
			}()
		} else {
			s.state = types.SessionState_SessionStatePending
			s.stateUpdate.Broadcast()
			err := s.trackerUpdateState(types.SessionState_SessionStateRunning)
			if err != nil {
				s.log.Warnf("Failed to set tracker state to %v", types.SessionState_SessionStateRunning)
			}

			go s.waitOnAccess()
		}
	}

	return nil
}

// allParticipants returns a list of all historical participants of the session.
func (s *session) allParticipants() []string {
	var participants []string
	for _, p := range s.partiesHistorical {
		participants = append(participants, p.Ctx.User.GetName())
	}

	return participants
}

// canStart checks if a session can start with the current set of participants.
func (s *session) canStart() (bool, auth.PolicyOptions, error) {
	var participants []auth.SessionAccessContext
	for _, party := range s.parties {
		if party.Ctx.User.GetName() == s.ctx.User.GetName() {
			continue
		}

		roleNames := party.Ctx.Identity.GetIdentity().Groups
		roles, err := getRolesByName(s.forwarder, roleNames)
		if err != nil {
			return false, auth.PolicyOptions{}, trace.Wrap(err)
		}

		participants = append(participants, auth.SessionAccessContext{
			Username: party.Ctx.User.GetName(),
			Roles:    roles,
			Mode:     party.Mode,
		})
	}

	yes, options, err := s.accessEvaluator.FulfilledFor(participants)
	return yes, options, trace.Wrap(err)
}

// Close terminates a session and disconnects all participants.
func (s *session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeOnce.Do(func() {
		s.BroadcastMessage("Closing session...")
		s.stateUpdate.L.Lock()
		defer s.stateUpdate.L.Unlock()
		s.state = types.SessionState_SessionStateTerminated
		s.io.Close()
		s.stateUpdate.Broadcast()
		err := s.trackerUpdateState(types.SessionState_SessionStateTerminated)
		if err != nil {
			s.log.Warnf("Failed to set tracker state to %v", types.SessionState_SessionStateTerminated)
		}

		s.log.Debugf("Closing session %v.", s.id.String())
		close(s.closeC)
		for id, party := range s.parties {
			err = party.Close()
			if err != nil {
				s.log.WithError(err).Errorf("Failed to disconnect party %v", id.String())
			}
		}

		if s.recorder != nil {
			s.recorder.Close(s.forwarder.ctx)
		}
	})

	return nil
}

func getRolesByName(forwarder *Forwarder, roleNames []string) ([]types.Role, error) {
	var roles []types.Role

	for _, roleName := range roleNames {
		role, err := forwarder.cfg.CachingAuthClient.GetRole(context.TODO(), roleName)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		roles = append(roles, role)
	}

	return roles, nil
}

func (s *session) trackerGet() (types.SessionTracker, error) {
	sess, err := s.forwarder.cfg.AuthClient.GetSessionTracker(s.forwarder.ctx, s.id.String())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return sess, nil
}

func (s *session) trackerCreate(p *party, policySets []*types.SessionTrackerPolicySet) error {
	initiator := &types.Participant{
		ID:         p.ID.String(),
		User:       p.Ctx.User.GetName(),
		LastActive: time.Now().UTC(),
	}

	req := &proto.CreateSessionTrackerRequest{
		ID:                s.id.String(),
		Namespace:         defaults.Namespace,
		Type:              string(types.KubernetesSessionKind),
		Hostname:          s.podName,
		ClusterName:       s.ctx.teleportCluster.name,
		Initiator:         initiator,
		Expires:           s.expires,
		KubernetesCluster: s.ctx.kubeCluster,
		HostUser:          initiator.User,
		HostPolicies:      policySets,
		Login:             "root",
	}

	_, err := s.forwarder.cfg.AuthClient.CreateSessionTracker(s.forwarder.ctx, req)
	return trace.Wrap(err)
}

func (s *session) trackerAddParticipant(participant *party) error {
	s.log.Debugf("Tracking participant: %v", participant.ID.String())
	req := &proto.UpdateSessionTrackerRequest{
		SessionID: s.id.String(),
		Update: &proto.UpdateSessionTrackerRequest_AddParticipant{
			AddParticipant: &proto.SessionTrackerAddParticipant{
				Participant: &types.Participant{
					ID:         participant.ID.String(),
					User:       participant.Ctx.User.GetName(),
					Mode:       string(participant.Mode),
					LastActive: time.Now().UTC(),
				},
			},
		},
	}

	err := s.forwarder.cfg.AuthClient.UpdateSessionTracker(s.forwarder.ctx, req)
	return trace.Wrap(err)
}

func (s *session) trackerRemoveParticipant(participantID string) error {
	s.log.Debugf("Not tracking participant: %v", participantID)
	req := &proto.UpdateSessionTrackerRequest{
		SessionID: s.id.String(),
		Update: &proto.UpdateSessionTrackerRequest_RemoveParticipant{
			RemoveParticipant: &proto.SessionTrackerRemoveParticipant{
				ParticipantID: participantID,
			},
		},
	}

	err := s.forwarder.cfg.AuthClient.UpdateSessionTracker(s.forwarder.ctx, req)
	return trace.Wrap(err)
}

func (s *session) trackerUpdateState(state types.SessionState) error {
	req := &proto.UpdateSessionTrackerRequest{
		SessionID: s.id.String(),
		Update: &proto.UpdateSessionTrackerRequest_UpdateState{
			UpdateState: &proto.SessionTrackerUpdateState{
				State: state,
			},
		},
	}

	err := s.forwarder.cfg.AuthClient.UpdateSessionTracker(s.forwarder.ctx, req)
	return trace.Wrap(err)
}
