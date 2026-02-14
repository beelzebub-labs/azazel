package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/azazel/internal/container"
	"github.com/azazel/internal/output"
	"github.com/azazel/internal/tracer"
	"github.com/spf13/cobra"
)

var (
	Version = "dev"

	containerIDs []string
	outputFile   string
	pretty       bool
	stdout       bool
	verbose      bool
	noSummary    bool
)

var rootCmd = &cobra.Command{
	Use:   "azazel",
	Short: "Linux Runtime Security and Forensics using eBPF",
	Long:  `Azazel — Linux Runtime Security and Forensics using eBPF. A lightweight eBPF-based runtime security tracer designed for malware analysis sandboxes.`,
	RunE:  runTrace,
}

var listContainersCmd = &cobra.Command{
	Use:   "list-containers",
	Short: "List running containers",
	RunE: func(cmd *cobra.Command, args []string) error {
		containers := container.ListContainers()
		if len(containers) == 0 {
			fmt.Println("No containers found.")
			return nil
		}
		fmt.Printf("%-14s %s\n", "CONTAINER ID", "PID")
		for _, c := range containers {
			fmt.Printf("%-14s %d\n", c.ID, c.PID)
		}
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("azazel %s\n", Version)
	},
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&containerIDs, "container", "c", nil, "container ID(s) to filter")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file path (default: stdout)")
	rootCmd.PersistentFlags().BoolVar(&pretty, "pretty", false, "pretty-print JSON")
	rootCmd.PersistentFlags().BoolVar(&stdout, "stdout", false, "also print to stdout when --output is set")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	rootCmd.PersistentFlags().BoolVar(&noSummary, "no-summary", false, "disable summary on exit")

	rootCmd.AddCommand(listContainersCmd)
	rootCmd.AddCommand(versionCmd)
}

// Execute is the entry point for the CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runTrace(cmd *cobra.Command, args []string) error {
	log.SetPrefix("")
	log.SetFlags(0)

	log.Println("[azazel] Starting...")

	// Set up output writer
	writer, err := output.NewWriter(outputFile, stdout, pretty)
	if err != nil {
		return fmt.Errorf("create writer: %w", err)
	}
	defer writer.Close()

	// Set up container resolver
	resolver := container.NewResolver()

	// Event handler
	handler := func(ev *tracer.ParsedEvent) {
		// Resolve container ID
		ev.ContainerID = resolver.Resolve(ev.CgroupID, ev.PID)
		writer.WriteEvent(ev)
	}

	// Create tracer
	cfg := tracer.Config{
		ContainerIDs: containerIDs,
		Verbose:      verbose,
		Handler:      handler,
	}

	t, err := tracer.New(cfg)
	if err != nil {
		return fmt.Errorf("create tracer: %w", err)
	}
	defer t.Close()

	// Set up container filters if specified
	if len(containerIDs) > 0 {
		for _, id := range containerIDs {
			cgroupID, err := container.GetCgroupIDForContainer(id)
			if err != nil {
				log.Printf("[azazel] Warning: could not resolve cgroup for container %s: %v", id, err)
				continue
			}
			if err := t.AddCgroupFilter(cgroupID); err != nil {
				log.Printf("[azazel] Warning: could not add cgroup filter for %s: %v", id, err)
				continue
			}
			log.Printf("[azazel] Filtering container: %s (cgroup_id=%d)", id, cgroupID)
		}
	}

	// Signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("[azazel] Received signal %s, shutting down...", sig)
		cancel()
	}()

	log.Println("[azazel] Tracing started. Press Ctrl+C to stop.")

	// Run the tracer
	if err := t.Run(ctx); err != nil {
		return fmt.Errorf("run tracer: %w", err)
	}

	// Print summary
	if !noSummary {
		writer.PrintSummary(os.Stderr)
	}

	log.Println("[azazel] Shutdown complete.")
	return nil
}
