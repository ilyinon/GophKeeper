// Command gophkeeper-client runs the GophKeeper CLI client.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/oilyin/gophkeeper/internal/transport/cli"
)

var (
	buildVersion = "dev"
	buildDate    = "unknown"
)

func main() {
	root := cli.NewRootCommand(cli.VersionInfo{Version: buildVersion, Date: buildDate})
	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
