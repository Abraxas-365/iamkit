package main

import (
	"os"

	"github.com/Abraxas-365/iamkit/cmd/iam/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		os.Exit(1)
	}
}
