package exo

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/sign"
	"gopkg.in/yaml.v3"
)

// certExecution is a helper function that reads in a yaml file and generates a certificate
// Note: service name can be empty, that is handled within the function
func (cli *exoskeleton) certExecution() error {

	// read in yaml file
	if cli.config.Certs.Filename == "" {
		return fmt.Errorf("no file specified for certificate generation")
	}

	// check for yaml file extension
	if len(cli.config.Certs.Filename) <= 4 {
		if cli.config.Certs.Filename[len(cli.config.Certs.Filename)-4:] != ".yml" ||
			cli.config.Certs.Filename[len(cli.config.Certs.Filename)-5:] != ".yaml" {
			return fmt.Errorf("cert config data file must have a .yaml or .yml extension")
		}
		return fmt.Errorf("cert config data file must have a .yaml or .yml extension")
	}

	// read in yaml file
	yml, err := os.Open(cli.config.Certs.Filename)
	if err != nil {
		return fmt.Errorf("error reading in yaml file: %v", err)
	}
	defer yml.Close()

	// decode to CertFile struct
	var certData CertData
	decoder := yaml.NewDecoder(yml)
	if err := decoder.Decode(&certData); err != nil {
		return fmt.Errorf("error decoding yaml file: %v", err)
	}

	// build cert template fields
	// compose cert name
	// naming convention: target_type_env, eg., db_server_dev or service_ca_prod
	name := strings.Builder{}
	if certData.Target != "" {
		name.WriteString(string(certData.Target))
		name.WriteString("_")
	} else {
		return errors.New("you must specify a target in yaml for cert generation")
	}
	if certData.Type != "" {
		name.WriteString(string(certData.Type))
		name.WriteString("_")
	} else {
		return errors.New("you must specify a type in yaml for cert generation")
	}
	if cli.config.Env != "" {
		name.WriteString(cli.config.Env)
	} else {
		return errors.New("you must specifcy environment (eg: '-e dev') for cert generation")
	}

	var r sign.CertRole
	switch role := string(certData.Type); role {
	case "ca":
		r = sign.CA
	case "server":
		r = sign.Server
	case "client":
		r = sign.Client
	default:
		return fmt.Errorf("invalid cert role: %s", role)
	}

	var caName string // will be blank if ca
	if r != sign.CA {
		caName = name.String()
	}

	ips := make([]net.IP, len(certData.SanIps))
	for _, ip := range certData.SanIps {
		ips = append(ips, net.ParseIP(ip))
	}

	// pre-pend service name to cert name if applicable (ie, it is not a ca)
	certName := name.String()
	if cli.config.ServiceName != "" {
		certName = fmt.Sprintf("%s_%s", cli.config.ServiceName, certName)
	}

	// build cert data fields struct
	fields := sign.CertData{
		CertName:     certName,
		Organisation: []string{certData.Organisation},
		CommonName:   certData.CommonName,
		San:          certData.San,
		SanIps:       ips,
		Role:         r,
		CaCertName:   caName,
	}

	// instantiate the certificate builder interface
	builder := sign.NewCertBuilder(fields)

	// generate cert
	switch certData.Crypto {
	case util.Ecdsa:
		if err := builder.GenerateEcdsaCert(); err != nil {
			return fmt.Errorf("error generating ecdsa cert/key pair: %v", err)
		}
	case util.Rsa:
		// TODO implement rsa cert generation
	default:
		return fmt.Errorf("invalid crypto algorithm: %s", certData.Crypto)
	}

	return nil
}
