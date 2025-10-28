package exo

import (
	"fmt"

	"github.com/tdeslauriers/carapace/internal/util"
)

// blindIndexExecution generates a blind index for a record field value using a secret stored in 1password.
func (e *exoskeleton) blindIndexExecution() (string, error) {

	// get the service name and env from the config
	serviceName := e.config.ServiceName
	if serviceName == "" {
		return "", fmt.Errorf("service name is required to generate blind index")
	}

	env := e.config.Env
	if env == "" {
		return "", fmt.Errorf("environment is required to generate blind index")
	}

	// build the aes 1password item name
	secretName := fmt.Sprintf("%s_hmac_index_secret_%s", serviceName, env)

	// generate the blind index
	blindIndex, err := e.indexer.BuildHmacIndex(e.config.BlindIndex, secretName, util.OpVaultName)
	if err != nil {
		return "", fmt.Errorf("error generating blind index: %v", err)
	}

	return blindIndex, nil
}
