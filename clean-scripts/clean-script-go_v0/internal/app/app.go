package app

import (
	"github.com/example/clean-script-go/internal/codex"
	"github.com/example/clean-script-go/internal/config"
	"github.com/example/clean-script-go/internal/fileops"
	"github.com/example/clean-script-go/internal/httpapi"
	"github.com/example/clean-script-go/internal/manager"
	"github.com/example/clean-script-go/internal/scanner"
	"go.uber.org/fx"
)

func New() *fx.App {
	return fx.New(
		config.Module,
		fileops.Module,
		codex.Module,
		scanner.Module,
		manager.Module,
		httpapi.Module,
	)
}
