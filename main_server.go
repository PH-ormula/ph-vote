//go:build !wasm
// +build !wasm

package main

import (
	"log"
	"net/http"

	"github.com/maxence-charriere/go-app/v9/pkg/app"
	"ph-vote/api"
	"ph-vote/backend"
	"ph-vote/config"
	"ph-vote/frontend"
)

func main() {
	mainApp := &frontend.MainApp{}
	app.Route("/", mainApp)
	app.Route("/admin", mainApp)
	app.RunWhenOnBrowser()

	err := config.Load("config.toml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	backend.InitDB()
	if err := backend.InitCrypto(); err != nil {
		log.Fatalf("Failed to init crypto: %v", err)
	}

	http.HandleFunc(api.PathRequestMagicLink, backend.HandleRequestMagicLink)
	http.HandleFunc(api.PathSignToken, backend.HandleSignToken)
	http.HandleFunc(api.PathVote, backend.HandleVote)
	http.HandleFunc(api.PathAdminVotes, backend.HandleAdminVotes)
	http.HandleFunc(api.PathAdminClearDB, backend.HandleAdminClearDB)
	http.HandleFunc(api.PathResults, backend.HandleResults)
	http.HandleFunc(api.PathConfig, backend.HandleConfig)

	// Since we are outputting wasm to build/app.wasm, we can intercept /web/app.wasm
	http.HandleFunc("/web/app.wasm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		http.ServeFile(w, r, "build/app.wasm")
	})

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))

	http.Handle("/", &app.Handler{
		Name:        config.Current.Title,
		Description: "Interactive Anonymous Voting",
		Styles: []string{
			"/web/app.css",
		},
	})

	log.Println("Server started on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
