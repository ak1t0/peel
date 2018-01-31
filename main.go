package main

import (
	"bufio"
	"fmt"
	"github.com/ak1t0/peel/scanner"
	"github.com/urfave/cli"
	"log"
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
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "f",
			Usage: "Select log file",
		},
	},
}

func doScan(c *cli.Context) error {
	filename := "data1.txt"
	if c.String("f") != "" {
		filename = c.String("f")
	}
	file, err := os.Open(filename)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	var target []string
	for s.Scan() {
		target = append(target, "http://"+s.Text())
	}
	onions := scanner.NewOnions(target)
	scanner.ScanOnions(&onions)
	fmt.Println(onions)
	return nil
}
