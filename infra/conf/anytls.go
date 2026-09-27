package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

type AnyTLSClientConfig struct {
	Address                  *Address `json:"address"`
	Port                     uint16   `json:"port"`
	Password                 string   `json:"password"`
	IdleSessionCheckInterval uint32   `json:"idleSessionCheckInterval"`
	IdleSessionTimeout       uint32   `json:"idleSessionTimeout"`
	MinIdleSession           uint32   `json:"minIdleSession"`
}

func (c *AnyTLSClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New(`anytls: "address" is not set`)
	}
	if c.Password == "" {
		return nil, errors.New(`anytls: "password" is not set`)
	}
	return &anytls.ClientConfig{
		Address:                  c.Address.String(),
		Port:                     uint32(c.Port),
		Password:                 c.Password,
		IdleSessionCheckInterval: c.IdleSessionCheckInterval,
		IdleSessionTimeout:       c.IdleSessionTimeout,
		MinIdleSession:           c.MinIdleSession,
	}, nil
}

type AnyTLSServerConfig struct {
	Password string `json:"password"`
}

func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	if c.Password == "" {
		return nil, errors.New(`anytls: "password" is not set`)
	}
	return &anytls.ServerConfig{
		Password: c.Password,
	}, nil
}
