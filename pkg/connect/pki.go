package connect

// base64'd *.pem file --> container env vars --> k8s secret
type Pki struct {
	CertFile string
	KeyFile  string
	CaFiles  []string
}
