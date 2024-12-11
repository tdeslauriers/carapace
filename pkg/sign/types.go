package sign

import "net"

type CertRole int

const (
	CA CertRole = iota
	Server
	Client
)

// CertData is a model representing the data a user needs to provide for cert generation 
type CertData struct {
	CertName     string
	Organisation []string
	CommonName   string // org + signature algo, leaf: domain
	San          []string
	SanIps       []net.IP
	Role         CertRole
	CaCertName   string
}
