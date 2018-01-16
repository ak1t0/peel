package main

import (
	"github.com/ak1t0/peel/scanner"
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
	app.Commands = Commands
	app.Copyright = "(c) 2018 ak1t0"

	app.Run(os.Args)
}

var Commands = []cli.Command{
	commandScan,
}

var commandScan = cli.Command{
	Name:    "scan",
	Usage:   "Scan onion service",
	Aliases: []string{"s"},
	Action:  doScan,
}

func doScan(c *cli.Context) error {
	var target = []string{"http://jbwocj4f64dkfiwv.onion"}
	onions := scanner.NewOnions(target)
	for _, onion := range onions {
		scanner.Scan(onion)
	}
	return nil
}
