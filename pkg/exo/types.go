package exo

import (
	"github.com/tdeslauriers/carapace/internal/util"
)

// Config is the configuration for the exo cli command.
// It contains the values parsed from the command line flags.
type Config struct {
	ServiceName string
	Env         string
	Certs       Certs
	Secret      string // name of secret to generate
	KeyPair     bool
	ByteLength int // length of secret to generate; need to set defaults if not set
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
	Certificate Certificate `yaml:"certificate"`
	OnePassword OnePassword `yaml:"one_password"`
}

// Certifcate is a model for the yaml data fields that the exo service
// needs to read in to populate the certifcate template.
type Certificate struct {
	Target       util.CertTarget `yaml:"target"` // choice is db or service
	Type         util.CertType   `yaml:"type"`   // choice is ca, server, or client
	Crypto       util.CryptoAlgo `yaml:"crypto"` // choice is rsa or ecdsa
	Organisation string          `yaml:"org"`
	CommonName   string          `yaml:"common_name"`
	San          []string        `yaml:"san"`
	SanIps       []string        `yaml:"san_ips"`
}

// OnePassword is a model representing the data to serialize from a yaml file
// that is needed by the exo cli to generate certifcates and put them in 1password correctly.
type OnePassword struct {
	Vault string   `yaml:"vault"`
	Tags  []string `yaml:"tags"`
}
