package main

import (
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/internal/util"

	"github.com/tdeslauriers/carapace/pkg/exo"
)

func main() {
	logger := slog.Default().With(slog.String(util.ComponentKey, util.ComponentMain))

	config, _ := exo.Parse()
	exoskeleton := exo.New(*config)
	if err := exoskeleton.Execute(); err != nil {
		logger.Error(fmt.Sprintf("error executing exo command: %v", err))
	}
}
