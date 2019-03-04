package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "0.2.0"
	githash = "HEAD"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("poke-ssl-agent %s (%s)\n", version, githash)
	},
}
