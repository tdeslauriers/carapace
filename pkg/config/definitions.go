package config

type ServerTls string

const (
	StandardTls ServerTls = "standard"
	MutualTls   ServerTls = "mutual"
)

type SvcDefinition struct {
	ServiceName string
	Tls         ServerTls
	Requires    Requires
}

type Requires struct {
	Client           bool
	Db               bool
	IndexKey         bool
	AesKey           bool
	UserAuthUrl      bool
	S2sSigningKey    bool
	S2sVerifyingKey  bool
	UserSigningKey   bool
	UserVerifyingKey bool
}
