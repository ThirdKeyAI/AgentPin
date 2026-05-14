package main

import (
	"fmt"

	"github.com/ThirdKeyAi/agentpin/go/internal/version"
)

func runVersion() {
	fmt.Printf("agentpin %s (protocol %s, bundle %s)\n",
		version.Version, version.ProtocolVersion, version.BundleVersion)
}
