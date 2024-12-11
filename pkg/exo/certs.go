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
	var data CertData
	decoder := yaml.NewDecoder(yml)
	if err := decoder.Decode(&data); err != nil {
		return fmt.Errorf("error decoding yaml file: %v", err)
	}

	// build cert template fields
	// compose cert name
	// naming convention: target_type_env, eg., db_server_dev or service_ca_prod
	name := strings.Builder{}

	// target chunk of naming convention
	if data.Certificate.Target != "" {
		name.WriteString(string(data.Certificate.Target))
		name.WriteString("_")
	} else {
		return errors.New("you must specify a target in yaml for cert generation")
	}

	// type chunk of naming convention
	if data.Certificate.Type != "" {
		name.WriteString(string(data.Certificate.Type))
		name.WriteString("_")
	} else {
		return errors.New("you must specify a type in yaml for cert generation")
	}

	// env chunk of naming convention
	if cli.config.Env != "" {
		name.WriteString(cli.config.Env)
	} else {
		return errors.New("you must specifcy environment (eg: '-e dev') for cert generation")
	}

	// determine cert role
	var r sign.CertRole
	switch role := data.Certificate.Type; role {
	case util.CA:
		r = sign.CA
	case util.Server:
		r = sign.Server
	case util.Client:
		r = sign.Client
	default:
		return fmt.Errorf("invalid cert role: %s", role)
	}

	// set ca name if applicable
	var caName string // will be blank if ca
	if r != sign.CA {
		// eg., db_ca_dev, or service_ca_prod
		caName = fmt.Sprintf("%s_%s_%s", data.Certificate.Target, util.CA, cli.config.Env)
	}

	// parse san ip addresses
	ips := make([]net.IP, 0, len(data.Certificate.SanIps))
	for _, ip := range data.Certificate.SanIps {
		ips = append(ips, net.ParseIP(ip))
	}

	// pre-pend service name to cert name if applicable (ie, it is not a ca)
	certName := name.String()
	if cli.config.ServiceName != "" {
		certName = fmt.Sprintf("%s_%s", cli.config.ServiceName, certName)
	}

	// build cert data fields struct
	fields := sign.CertFields{
		CertName:     certName,
		Organisation: []string{data.Certificate.Organisation},
		CommonName:   data.Certificate.CommonName,
		San:          data.Certificate.San,
		SanIps:       ips,
		Role:         r,
		CaCertName:   caName,

		// 1password fields
		OpVault: data.OnePassword.Vault,
		OpTags:  data.OnePassword.Tags,
	}

	// generate cert
	switch data.Certificate.Crypto {
	case util.Ecdsa:
		if err := cli.certs.GenerateEcdsaCert(fields); err != nil {
			return fmt.Errorf("%s", err)
		}
	case util.Rsa:
		// TODO implement rsa cert generation
	default:
		return fmt.Errorf("invalid crypto algorithm: %s", data.Certificate.Crypto)
	}

	return nil
}
