package exo

import (
	"github.com/tdeslauriers/carapace/internal/util"
)

// Config is the configuration for the exo cli command.
// It contains the values parsed from the command line flags.
type Config struct {
	Certs Certs
}

// Certs is a struct for the exo cli command to consume.
// It contains the values parsed from the command line flags.
// Intent is that it can read in a file from the os that constains the
// values for the sign.CertFields struct ==> cert template.
type Certs struct {
	Invoked  bool
	Filename string
}

// CertData is a model representing the data to serialize from a yaml file
// that is read in by the exo cli cert command.
type CertData struct {
	Type         util.CertType   `yaml:"type"`   // choice is ca, server, or client
	Target       util.CertTarget `yaml:"target"` // choice is db or server
	Crypto       util.CryptoAlgo `yaml:"crypto"` // choice is rsa or ecdsa
	Organisation string          `yaml:"org"`
	CommonName   string          `yaml:"common_name"`
	San          []string        `yaml:"san"`
	SanIps       []string        `yaml:"san_ips"`
}
