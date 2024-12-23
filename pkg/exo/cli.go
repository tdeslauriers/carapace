package exo

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/sign"
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
		certs:  sign.NewCertBuilder(),
		keyGen: sign.NewKeyGenerator(),

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentExo)),
	}
}

var _ Exoskeleton = (*exoskeleton)(nil)

// exoskeleton is the concrete implementation of the Exo interface.
type exoskeleton struct {
	config Config
	certs  sign.CertBuilder
	keyGen sign.KeyGenerator

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

	// jwt signing key pair
	keyPairMsg := "invokes ecdsa jwt signing key pair generation"
	keyPair := flag.Bool("key-pair", false, keyPairMsg)
	flag.BoolVar(keyPair, "k", false, keyPairMsg)

	// environment
	envMsg := "applies environment tag/instruction to applicable fields in exo commands"
	env := flag.String("env", "", envMsg)
	flag.StringVar(env, "e", "", envMsg)

	// service name
	svcNameMsg := "applies service name to applicable fields in exo commands"
	svcName := flag.String("service", "", svcNameMsg)
	flag.StringVar(svcName, "s", "", svcNameMsg)

	// file
	fileMsg := "imports a file, often containing necessary data for exo fuctionality"
	file := flag.String("file", "", fileMsg)
	flag.StringVar(file, "f", "", fileMsg)

	// help message
	flag.Usage = func() {

		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -c, --certs    %s\n", certMsg)
		fmt.Fprintf(os.Stderr, "  -k, --key-pair %s\n", keyPairMsg)
		fmt.Fprintf(os.Stderr, "  -e, --env      %s\n", envMsg)
		fmt.Fprintf(os.Stderr, "  -s, --service  %s\n", svcNameMsg)
		fmt.Fprintf(os.Stderr, "  -f, --file     %s\n", fileMsg)
		fmt.Fprintf(os.Stderr, "  -h             Display this help message\n")
	}

	// parse flags
	flag.Parse()

	return &Config{
		ServiceName: *svcName,
		Env:         *env,
		Certs: Certs{
			Invoked:  *certs,
			Filename: *file,
		},
		KeyPair: *keyPair,
	}, nil
}

// Execute is the method that will execute the commands defined in the config struct
func (cli *exoskeleton) Execute() error {

	// certifcate generation execution
	if cli.config.Certs.Invoked {
		if err := cli.certExecution(); err != nil {
			return fmt.Errorf("error executing cert command: %v", err)
		}
	}

	// jwt key pair generation execution
	if cli.config.KeyPair {

		// check for service name
		if cli.config.ServiceName == "" {
			return fmt.Errorf("you must specify a service name for key pair generation, eg., '-s shaw'")
		}

		// check for environment
		if cli.config.Env == "" {
			return fmt.Errorf("you must specify an environment for key pair generation, eg., '-e dev'")
		}

		if err := cli.keyPairExecution(); err != nil {
			return fmt.Errorf("error executing key pair command: %v", err)
		}
	}

	return nil
}
