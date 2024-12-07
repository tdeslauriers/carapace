package util

// CertType represents the type of certificate.
// choice is ca, server, or client
type CertType string

const (
	CA     CertType = "ca"
	Server CertType = "server"
	Client CertType = "client"
)

// CertTarget represents the target of the certificate.
type CertTarget string

const (
	Db   CertTarget = "db"
	Serv CertTarget = "server"
)

// CryptoAlgo represents the type of cryptographic algorithm.
type CryptoAlgo string

const (
	Rsa   CryptoAlgo = "rsa"
	Ecdsa CryptoAlgo = "ecdsa"
)
