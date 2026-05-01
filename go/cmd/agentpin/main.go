// Command agentpin is the AgentPin CLI: keygen, issue, verify, bundle.
//
// It mirrors the Rust `agentpin` binary's subcommand surface to keep
// operator workflows portable across language stacks.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "keygen":
		err = runKeygen(args)
	case "issue":
		err = runIssue(args)
	case "verify":
		err = runVerify(args)
	case "bundle":
		err = runBundle(args)
	case "-h", "--help", "help":
		usage()
		return
	case "version", "--version", "-V":
		runVersion()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `agentpin — AgentPin credential management CLI

USAGE:
    agentpin <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    keygen    Generate a new ECDSA P-256 keypair
    issue     Issue an agent credential (JWT)
    verify    Verify an agent credential
    bundle    Create a trust bundle from discovery and revocation documents
    version   Print the AgentPin Go SDK version

Run 'agentpin <SUBCOMMAND> --help' for subcommand help.`)
}
