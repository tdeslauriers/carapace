package exo

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/internal/util"
)

// Exoskeleton is the Cli interface for carapace.
// It's purpose is to receive a config struct and execute the commands defined therein.
type Exoskeleton interface {

	// Execute is the method that will execute the commands defined in the config struct
	// of the Exo interface.  It will return an error to console if the command fails.
	Execute() error
}

// New is a factory function that returns a new Exo cli interface.
func New(config Config) Exoskeleton {
	return &exoskeleton{
		config: config,
		// place holder for 1password interface

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentExo)),
	}
}

var _ Exoskeleton = (*exoskeleton)(nil)

// exoskeleton is the concrete implementation of the Exo interface.
type exoskeleton struct {
	config Config

	logger *slog.Logger
}

// Parse is a helper function that reads in flags and args from the command line and
// returns a ptr to a Config struct or an error
func Parse() (*Config, error) {

	// flag declarations
	// certs
	certMsg := "invokes certificate generation based on a yaml file"
	certs := flag.Bool("certs", false, certMsg)
	flag.BoolVar(certs, "c", false, certMsg)

	// file
	fileMsg := "imports a file, often containing necessary data for exo fuctionality"
	certFile := flag.String("file", "", fileMsg)
	flag.StringVar(certFile, "f", "", fileMsg)

	// help message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -c, --certs  %s\n", certMsg)
		fmt.Fprintf(os.Stderr, "  -f, --file   %s\n", fileMsg)
		fmt.Fprintf(os.Stderr, "  -h           Display this help message\n")
	}

	// parse flags
	flag.Parse()

	return &Config{
		Certs: Certs{
			Invoked:  *certs,
			Filename: *certFile,
		},
	}, nil
}

// Execute is the method that will execute the commands defined in the config struct
func (exo *exoskeleton) Execute() error {
	return nil
}
