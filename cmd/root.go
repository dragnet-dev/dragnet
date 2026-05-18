package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var version = "dev"

var cfgFile string

var rootCmd = &cobra.Command{
	Use:     "dragnet",
	Short:   "Dragnet — open source supply chain threat intelligence engine",
	Version: version,
	Long: `Dragnet polls intelligence sources, merges incidents, generates Sigma rules,
and compiles them to detection rules for every major SIEM and detection platform.`,
}

// dataDir returns the directory containing the config file, used as the base
// for all relative data paths (state/, actors/, module output dirs).
func dataDir() string {
	return filepath.Dir(cfgFile)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "dragnet.yaml",
		"Path to dragnet.yaml config file")
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(enrichCmd)
	rootCmd.AddCommand(updatePopularCmd)
	rootCmd.AddCommand(manifestCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(migrateIDsCmd)
	rootCmd.AddCommand(pruneDraftsCmd)
}
