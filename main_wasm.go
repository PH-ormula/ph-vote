//go:build wasm
// +build wasm

package main

import (
	"github.com/maxence-charriere/go-app/v9/pkg/app"
	"ph-vote/frontend"
)

func main() {
	mainApp := &frontend.MainApp{}
	app.Route("/", mainApp)
	app.Route("/admin", mainApp)
	app.RunWhenOnBrowser()
}
