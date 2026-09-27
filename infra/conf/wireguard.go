package conf

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

type WireGuardPeerConfig struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    uint32   `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`

	// AmneziaWG obfuscation parameters.
	JunkPacketCount           uint32   `json:"junkPacketCount,omitempty"`
	JunkPacketMinSize         uint32   `json:"junkPacketMinSize,omitempty"`
	JunkPacketMaxSize         uint32   `json:"junkPacketMaxSize,omitempty"`
	InitPacketJunkSize        uint32   `json:"initPacketJunkSize,omitempty"`
	ResponsePacketJunkSize    uint32   `json:"responsePacketJunkSize,omitempty"`
	InitPacketJunkHeader      []uint32 `json:"initPacketJunkHeader,omitempty"`
	ResponsePacketJunkHeader  []uint32 `json:"responsePacketJunkHeader,omitempty"`
	CookiePacketJunkHeader    []uint32 `json:"cookiePacketJunkHeader,omitempty"`
	TransportPacketJunkHeader []uint32 `json:"transportPacketJunkHeader,omitempty"`

	Level uint32 `json:"level"`
	Email string `json:"email"`
}

func (c *WireGuardPeerConfig) Build() (*wireguard.PeerConfig, error) {
	var err error
	config := new(wireguard.PeerConfig)

	if c.PublicKey != "" {
		config.PublicKey, err = ParseWireGuardKey(c.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	if c.PreSharedKey != "" {
		config.PreSharedKey, err = ParseWireGuardKey(c.PreSharedKey)
		if err != nil {
			return nil, err
		}
	}

	config.Endpoint = c.Endpoint
	if c.KeepAlive != 0 {
		config.KeepAlive = strconv.FormatUint(uint64(c.KeepAlive), 10)
	}
	// AmneziaWG junk packet params.
	config.JunkPacketCount = c.JunkPacketCount
	config.JunkPacketMinSize = c.JunkPacketMinSize
	config.JunkPacketMaxSize = c.JunkPacketMaxSize
	config.InitPacketJunkSize = c.InitPacketJunkSize
	config.ResponsePacketJunkSize = c.ResponsePacketJunkSize
	config.InitPacketJunkHeader = c.InitPacketJunkHeader
	config.ResponsePacketJunkHeader = c.ResponsePacketJunkHeader
	config.CookiePacketJunkHeader = c.CookiePacketJunkHeader
	config.TransportPacketJunkHeader = c.TransportPacketJunkHeader
	if c.AllowedIPs == nil {
		config.AllowedIps = []string{"0.0.0.0/0", "::0/0"}
	} else {
		config.AllowedIps = c.AllowedIPs
	}

	return config, nil
}

type WireGuardConfig struct {
	IsClient bool `json:""`

	NoKernelTun bool                   `json:"noKernelTun"`
	SecretKey   string                 `json:"secretKey"`
	Address     []string               `json:"address"`
	Peers       []*WireGuardPeerConfig `json:"peers"`
	MTU         int32                  `json:"mtu"`
	Reserved    []byte                 `json:"reserved"`
	DNS         []string               `json:"remoteDNS"`
}

func (c *WireGuardConfig) Build() (proto.Message, error) {
	config := new(wireguard.DeviceConfig)

	var err error
	config.SecretKey, err = ParseWireGuardKey(c.SecretKey)
	if err != nil {
		return nil, errors.New("invalid WireGuard secret key: %w", err)
	}

	if c.Address == nil {
		// bogon ips
		config.Endpoint = []string{"10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"}
	} else {
		config.Endpoint = c.Address
	}

	if c.IsClient {
		config.Peers = make([]*wireguard.PeerConfig, len(c.Peers))
		for i, p := range c.Peers {
			msg, err := p.Build()
			if err != nil {
				return nil, err
			}
			config.Peers[i] = msg
		}
	} else {
		config.Users = make([]*protocol.User, len(c.Peers))
		processUser := func(idx int) error {
			p := c.Peers[idx]
			m, err := p.Build()
			if err != nil {
				return err
			}
			config.Users[idx] = &protocol.User{
				Email:   p.Email,
				Level:   p.Level,
				Account: serial.ToTypedMessage(m),
			}
			return nil
		}
		if err := task.ParallelForN(len(c.Peers), processUser); err != nil {
			return nil, err
		}
	}

	if c.MTU == 0 {
		config.Mtu = 1420
	} else {
		config.Mtu = c.MTU
	}

	if len(c.Reserved) != 0 && len(c.Reserved) != 3 {
		return nil, errors.New(`"reserved" should be empty or 3 bytes`)
	}
	config.Reserved = c.Reserved

	config.IsClient = c.IsClient
	config.NoKernelTun = c.NoKernelTun
	config.DNS = c.DNS

	return config, nil
}

func ParseWireGuardKey(str string) (string, error) {
	var err error

	if str == "" {
		return "", errors.New("key must not be empty")
	}

	if len(str) == 64 {
		_, err = hex.DecodeString(str)
		if err == nil {
			return str, nil
		}
	}

	var dat []byte
	str = strings.TrimSuffix(str, "=")
	if strings.ContainsRune(str, '+') || strings.ContainsRune(str, '/') {
		dat, err = base64.RawStdEncoding.DecodeString(str)
	} else {
		dat, err = base64.RawURLEncoding.DecodeString(str)
	}
	if err == nil {
		return hex.EncodeToString(dat), nil
	}

	return "", errors.New("failed to deserialize key").Base(err)
}
