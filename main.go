package main

import (
	_ "embed"
	"log"
	"os"

	"github.com/dutchcoders/transfer.sh/cmd"
	"github.com/dutchcoders/transfer.sh/server"
)

// CHANGELOG.md is embedded so the in-app /changelog.json endpoint can serve
// it without depending on the file being present in the container image.
//
//go:embed CHANGELOG.md
var changelogMD []byte

func main() {
	server.Changelog = changelogMD
	app := cmd.New()
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
