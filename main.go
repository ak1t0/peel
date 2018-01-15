package main

import (
	"github.com/urfave/cli"
	"os"
)

// Version number
var Version = "0.0.1"

func main() {
	app := cli.NewApp()
	app.Name = "peel"
	app.Usage = "scan offensively onion service"
	app.Version = Version
	app.Author = "ak1t0"
	app.Email = "aktoo3097@gmail.com"
	//app.Commands = Commands
	app.Copyright = "(c) 2018 ak1t0"

	app.Run(os.Args)
}
