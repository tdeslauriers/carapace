package config

type ServerTls string

const (
	StandardTls ServerTls = "standard"
	MutualTls   ServerTls = "mutual"
)

type SvcDefinition struct {
	name     string
	tlsType  ServerTls
	requires Requires
}

type Requires struct {
	client           bool
	db               bool
	indexKey         bool
	aesKey           bool
	userAuthUrl      bool
	s2sSigningKey    bool
	s2sVerifyingKey  bool
	userSigningKey   bool
	userVerifyingKey bool
}
