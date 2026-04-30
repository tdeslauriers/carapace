package main

import (
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/exo"
	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
	"github.com/tdeslauriers/carapace/pkg/sign"
)

func main() {
	logger := slog.Default().With(slog.String(util.ComponentKey, util.ComponentMain))

	config, _ := exo.Parse()

	// instantiate exo cli
	exoskeleton := exo.New(
		*config,
		data.NewSecretGenerator(onepassword.NewService(onepassword.NewCli())),
		sign.NewCertBuilder(),
		sign.NewKeyGenerator(),
		data.NewIndexBuilder(),
	)

	if err := exoskeleton.Execute(); err != nil {
		logger.Error(fmt.Sprintf("error executing exo command: %w", err))
	}
}
