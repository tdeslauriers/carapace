package exo

import "fmt"

func (e *exoskeleton) secretGenExecution() error {

	// check for required cli args
	if e.config.ServiceName == "" {
		return fmt.Errorf("service name is required to generate secrets")
	}

	if e.config.Env == "" {
		return fmt.Errorf("env is required to generate secrets")
	}

	// build seceret name
	secretName := fmt.Sprintf("%s_%s_secret_%s", e.config.ServiceName, e.config.Secret, e.config.Env)

	// generate jwt key pair
	if err := e.secretGen.Generate32ByteKey(secretName); err != nil {
		return fmt.Errorf("failed to generate secrets: %v", err)
	}

	return nil
}
