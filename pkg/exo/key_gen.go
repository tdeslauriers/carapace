package exo

import "fmt"

// keyPairExecution() is a helper function that executes the key pair generation process.
func (e *exoskeleton) keyPairExecution() error {

	// generate jwt key pair
	if err := e.keyGen.GenerateEcdsaSigningKey(e.config.ServiceName, e.config.Env); err != nil {
		return fmt.Errorf("failed to generate ecdsa keys: %v", err)
	}

	return nil
}
