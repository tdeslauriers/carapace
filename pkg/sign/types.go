package sign

import "net"

type CertRole int

const (
	CA CertRole = iota
	Server
	Client
)

// CertFields is a model representing the data a user needs to provide for cert generation
type CertFields struct {
	CertName     string
	Organisation []string
	CommonName   string // org + signature algo, leaf: domain
	San          []string
	SanIps       []net.IP
	Role         CertRole
	CaCertName   string

	// 1password fields
	OpVault string   // 1password vault name
	OpTags  []string // 1password tags needed if certifcate is created vs updated.
}
