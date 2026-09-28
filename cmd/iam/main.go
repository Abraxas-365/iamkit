package main

import (
	"fmt"
	"os"

	"github.com/Abraxas-365/iamkit/cmd/iam/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
