package exo

import (
	"fmt"
	"net"
	"os"

	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/sign"
	"gopkg.in/yaml.v3"
)

// certExecution is a helper function that reads in a yaml file and generates a certificate
// Note: service name can be empty, that is handled within the function
func certExecution(service, filename string) error {

	// read in yaml file
	if filename == "" {
		return fmt.Errorf("no file specified for certificate generation")
	}

	// check for yaml file extension
	if len(filename) <= 4 {
		if filename[len(filename)-4:] != ".yml" ||
			filename[len(filename)-5:] != ".yaml" {
			return fmt.Errorf("cert config data file must have a .yaml or .yml extension")
		}
		return fmt.Errorf("cert config data file must have a .yaml or .yml extension")
	}

	// read in yaml file
	yml, err := os.Open(filename)
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
	name := string(certData.Type)
	if certData.Target == util.Db {
		name = fmt.Sprintf("%s_%s", util.Db, name)
	}
	if service != "" {
		name = fmt.Sprintf("%s_%s", service, name)
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

	var caName string // will be blank if not ca
	if r != sign.CA {
		caName = name
	}

	ips := make([]net.IP, len(certData.SanIps))
	for _, ip := range certData.SanIps {
		ips = append(ips, net.ParseIP(ip))
	}

	fields := sign.CertFields{
		CertName:     name,
		Organisation: []string{certData.Organisation},
		CommonName:   certData.CommonName,
		San:          certData.San,
		SanIps:       ips,
		Role:         r,
		CaCertName:   caName,
	}

	// generate cert
	switch certData.Crypto {
	case util.Ecdsa:
		fields.GenerateEcdsaCert()
	case util.Rsa:
		// TODO implement rsa cert generation
	default:
		return fmt.Errorf("invalid crypto algorithm: %s", certData.Crypto)
	}

	return nil
}
