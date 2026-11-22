package anytls

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/anytls/uot"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// Client is the outbound handler for the AnyTLS proxy protocol. The actual
// TLS handshake and session multiplexing happen in the anytls transport
// dialer (transport/internet/anytls), reached through dialer.Dial — the
// same split as the hysteria protocol client.
type Client struct {
	server        net.Destination
	policyManager policy.Manager
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	if config.Address == "" {
		return nil, errors.New("anytls: address is not set")
	}

	dest := net.Destination{
		Address: net.ParseAddress(config.Address),
		Port:    net.Port(config.Port),
		Network: net.Network_TCP,
	}
	if !dest.IsValid() {
		return nil, errors.New("anytls: invalid address ", config.Address)
	}
	if dest.Port == 0 {
		dest.Port = 443
	}

	return &Client{
		server:        dest,
		policyManager: p,
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "anytls"
	ob.CanSpliceCopy = 3
	target := ob.Target

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
	}, sessionPolicy.Timeouts.ConnectionIdle)

	conn, err := dialer.Dial(ctx, c.server)
	if err != nil {
		return errors.New("anytls: failed to dial server").Base(err)
	}
	defer conn.Close()

	errors.LogInfo(ctx, "tunneling request to ", target, " via anytls ", c.server.NetAddr())

	if target.Network == net.Network_TCP {
		if err := M.SocksaddrSerializer.WriteAddrPort(conn, singbridge.ToSocksaddr(target)); err != nil {
			return errors.New("anytls: failed to write target").Base(err)
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}
		return nil
	}

	// UDP is carried over the anytls stream via UDP-over-TCP (UoT), the
	// same mechanism sing-box clients use.
	uotClient := &uot.Client{Version: uot.Version}
	uotConn, err := uotClient.DialConn(conn, false, singbridge.ToSocksaddr(target))
	if err != nil {
		return errors.New("anytls: failed to establish UoT").Base(err)
	}

	packetConn := &singbridge.PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Dest:   target,
		T: signal.CancelAfterInactivity(ctx, func() {
			common.Interrupt(link.Reader)
			common.Interrupt(conn)
		}, 300*time.Second),
	}
	return singbridge.ReturnError(bufio.CopyPacketConn(ctx, packetConn, bufio.NewPacketConn(uotConn)))
}
