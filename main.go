package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/antonmedv/jout/cmd/ls"
	"github.com/antonmedv/jout/cmd/ps"
)

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	if len(args) < 2 {
		usage()
		return 2
	}

	var code int
	var err error = nil

	switch args[1] {
	case "ls":
		code, err = ls.Run(args[2:])
	case "ps":
		code, err = ps.Run(args[2:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", args[1])
		usage()
		return 2
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
			fmt.Fprintf(os.Stderr, string(exitErr.Stderr))
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	}
	return code
}

func usage() {
	fmt.Fprintln(os.Stderr, "jout — Run commands, get JSON.")
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  jout ls [-P|-H|-L] [path...]")
	fmt.Fprintln(os.Stderr, "  jout ps [--user USER]")
}
