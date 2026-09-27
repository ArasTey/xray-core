package conf

import (
	"github.com/xtls/xray-core/transport/internet/anytls"
)

type AnyTLSConfig struct {
	Password string `json:"password"`
}

func (c *AnyTLSConfig) Build() (*anytls.Config, error) {
	return &anytls.Config{Password: c.Password}, nil
}
