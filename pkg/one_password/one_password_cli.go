package onepassword

// Cli is an interface for the one_password cli.
type Cli interface {
	
}

// New is a factory function that returns a new one_password cli interface.
func New() Cli {
	return &cli{}
}

var _ Cli = (*cli)(nil)

// cli is the concrete implementation of the Cli interface.
type cli struct {
}

