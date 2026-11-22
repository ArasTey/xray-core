package anytls

import (
	"context"
	"crypto/sha256"
	go_tls "crypto/tls"
	"encoding/binary"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport/internet"
	anytls_session "github.com/xtls/xray-core/transport/internet/anytls/anytls-session"
	"github.com/xtls/xray-core/transport/internet/anytls/padding"
	"github.com/xtls/xray-core/transport/internet/anytls/uot"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"

	"github.com/sagernet/sing/common/atomic"
	M "github.com/sagernet/sing/common/metadata"
)

const protocolName = "anytls"

type paddingHolder struct {
	value *atomic.TypedValue[*padding.PaddingFactory]
}

func newPaddingHolder() *paddingHolder {
	v := new(atomic.TypedValue[*padding.PaddingFactory])
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, v)
	return &paddingHolder{value: v}
}

type clientState struct {
	paddingFactory *paddingHolder
	client         *anytls_session.Client
	uotClient      *uot.Client
	dialFunc       func(ctx context.Context) (net.Conn, error)
	password       string
}

type dialerKey struct {
	dest          xnet.Destination
	streamSetting *internet.MemoryStreamConfig
}

type managerType struct {
	sync.RWMutex
	m map[dialerKey]*clientState
}

var (
	manager    *managerType
	managerOne sync.Once
)

func init() {
	internet.RegisterTransportDialer(protocolName, Dial)
}

func Dial(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("anytls: tls config is nil")
	}
	if transportSettings, ok := streamSettings.ProtocolSettings.(*Config); !ok || transportSettings == nil {
		return nil, errors.New("anytls: transport settings missing")
	}

	state := getState(dest, streamSettings)

	stream, err := state.client.CreateStream(ctx)
	if err != nil {
		return nil, errors.New("anytls: failed to create stream").Base(err)
	}
	return stat.Connection(stream), nil
}

func getState(dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) *clientState {
	managerOne.Do(func() {
		manager = &managerType{m: make(map[dialerKey]*clientState)}
	})
	manager.RLock()
	c := manager.m[dialerKey{dest, streamSettings}]
	manager.RUnlock()
	if c != nil {
		return c
	}
	manager.Lock()
	defer manager.Unlock()
	if c := manager.m[dialerKey{dest, streamSettings}]; c != nil {
		return c
	}
	innerTLS := tls.ConfigFromStreamSettings(streamSettings)
	goTLS := innerTLS.GetTLSConfig(tls.WithDestination(dest))
	transportCfg, _ := streamSettings.ProtocolSettings.(*Config)
	state := &clientState{
		paddingFactory: newPaddingHolder(),
		password:       transportCfg.GetPassword(),
	}
	state.dialFunc = func(ctx context.Context) (net.Conn, error) {
		conn, err := dialTLS(ctx, dest, goTLS, streamSettings)
		if err != nil {
			return nil, err
		}
		if err := writeAuthFrame(conn, state.password, state.paddingFactory.value); err != nil {
			conn.Close()
			return nil, errors.New("anytls: failed to send auth").Base(err)
		}
		return conn, nil
	}
	state.client = anytls_session.NewClient(context.Background(), singbridge.NewLogger(func(values ...any) *errors.Error {
		return errors.New(values...)
	}), state.dialFunc, state.paddingFactory.value, 0, 0, 0, false)
	state.uotClient = &uot.Client{
		Dialer:  &uotDialer{state: state},
		Version: uot.Version,
	}
	manager.m[dialerKey{dest, streamSettings}] = state
	return state
}

func dialTLS(ctx context.Context, dest xnet.Destination, config *go_tls.Config, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.(*tls.Conn).HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, errors.New("anytls: tls handshake failed").Base(err)
	}
	return tlsConn, nil
}

// uotDialer adapts session streams to the uot.Client dialer interface so
// UDP payloads can be carried over the multiplexed anytls session.
type uotDialer struct {
	state *clientState
}

func (d *uotDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	stream, err := d.state.client.CreateStream(ctx)
	if err != nil {
		return nil, errors.New("anytls: failed to create uot stream").Base(err)
	}
	return stream, nil
}

func (d *uotDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return &Config{}
	}))
}

// writeAuthFrame sends the anytls session authentication: sha256(password)
// followed by a 2-byte big-endian padding length and the padding bytes.
func writeAuthFrame(conn net.Conn, password string, paddingValue *atomic.TypedValue[*padding.PaddingFactory]) error {
	sum := sha256.Sum256([]byte(password))
	paddingLen := 0
	if pad := paddingValue.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	frame := make([]byte, 0, 32+2+paddingLen)
	frame = append(frame, sum[:]...)
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(paddingLen))
	frame = append(frame, lenBytes[:]...)
	if paddingLen > 0 {
		frame = append(frame, make([]byte, paddingLen)...)
	}
	_, err := conn.Write(frame)
	return err
}
