package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/azazel/internal/container"
	"github.com/azazel/internal/output"
	"github.com/azazel/internal/tracer"
	"github.com/spf13/cobra"
)

var (
	samplePath string
	timeout    time.Duration
	image      string
)

var runSandboxCmd = &cobra.Command{
	Use:   "run-sandbox",
	Short: "Run a malware sample in an isolated Docker sandbox and trace it",
	Long: `run-sandbox launches an isolated Docker container, injects a malware sample,
and automatically configures Azazel to trace only that container.

This command is ideal for automated malware analysis or AI agents (MCP/skills).`,
	Example: `  azazel run-sandbox --sample ./malware.elf --timeout 60s --output report.json`,
	RunE:    runSandbox,
}

func init() {
	runSandboxCmd.Flags().StringVarP(&samplePath, "sample", "s", "", "Path to the malware sample (required)")
	runSandboxCmd.MarkFlagRequired("sample")
	runSandboxCmd.Flags().DurationVarP(&timeout, "timeout", "t", 30*time.Second, "Maximum execution time for the sandbox")
	runSandboxCmd.Flags().StringVarP(&image, "image", "i", "ubuntu:22.04", "Docker image to use for the sandbox")
	
	rootCmd.AddCommand(runSandboxCmd)
}

func runSandbox(cmd *cobra.Command, args []string) error {
	log.SetPrefix("")
	log.SetFlags(0)

	absSamplePath, err := filepath.Abs(samplePath)
	if err != nil {
		return fmt.Errorf("failed to resolve sample path: %w", err)
	}

	if _, err := os.Stat(absSamplePath); os.IsNotExist(err) {
		return fmt.Errorf("sample file does not exist: %s", absSamplePath)
	}

	// 1. Start Tracer
	log.Println("[azazel] Starting tracer for sandbox analysis...")

	writer, err := output.NewWriter(outputFile, stdout, pretty)
	if err != nil {
		return fmt.Errorf("create writer: %w", err)
	}
	defer writer.Close()

	resolver := container.NewResolver()

	handler := func(ev *tracer.ParsedEvent) {
		ev.ContainerID = resolver.Resolve(ev.CgroupID, ev.PID)
		writer.WriteEvent(ev)
	}

	cfg := tracer.Config{
		ContainerIDs: []string{"DYNAMIC_SANDBOX"}, // dummy to force filter enable
		Verbose:      verbose,
		Handler:      handler,
	}

	t, err := tracer.New(cfg)
	if err != nil {
		return fmt.Errorf("create tracer: %w", err)
	}
	defer t.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run tracer in background
	go func() {
		if err := t.Run(ctx); err != nil {
			log.Printf("[azazel] Tracer stopped: %v", err)
		}
	}()

	// Give tracer a moment to attach programs
	time.Sleep(1 * time.Second)

	// 2. Launch Docker Container
	log.Printf("[azazel] Launching sandbox container (image: %s)...", image)
	
	// The entrypoint script sleeps for 1 second to give the Go CLI time to extract the Container ID
	// and add it to the eBPF filter map, then it copies and executes the sample.
	entrypointScript := fmt.Sprintf(`sleep 1; cp /malware_sample /tmp/sample; chmod +x /tmp/sample; /tmp/sample; sleep %d`, int(timeout.Seconds()))

	dockerArgs := []string{
		"run", "-d", "--rm",
		"--network", "none",
		"--cap-add", "NET_RAW",
		"--cap-add", "SYS_PTRACE",
		"--cpus", "1.0",
		"--memory", "512m",
		"--tmpfs", "/tmp:exec", // Allow execution in tmpfs
		"-v", fmt.Sprintf("%s:/malware_sample:ro", absSamplePath),
		image,
		"bash", "-c", entrypointScript,
	}

	dockerCmd := exec.Command("docker", dockerArgs...)
	var outBuf, errBuf bytes.Buffer
	dockerCmd.Stdout = &outBuf
	dockerCmd.Stderr = &errBuf

	if err := dockerCmd.Run(); err != nil {
		return fmt.Errorf("failed to start docker container: %w\nStderr: %s", err, errBuf.String())
	}

	containerID := strings.TrimSpace(outBuf.String())
	if len(containerID) > 12 {
		containerID = containerID[:12]
	}
	log.Printf("[azazel] Sandbox container started with ID: %s", containerID)

	// 3. Inject Container ID into eBPF filter
	// Retry loop because cgroup creation might take a few milliseconds
	var cgroupID uint64
	for i := 0; i < 20; i++ {
		cgroupID, err = container.GetCgroupIDForContainer(containerID)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err != nil {
		log.Printf("[azazel] Warning: could not resolve cgroup for container %s: %v. Events might not be captured.", containerID, err)
	} else {
		if err := t.AddCgroupFilter(cgroupID); err != nil {
			log.Printf("[azazel] Warning: could not add cgroup filter for %s: %v", containerID, err)
		} else {
			log.Printf("[azazel] Successfully filtered container %s (cgroup_id=%d) in kernel", containerID, cgroupID)
		}
	}

	// 4. Wait for completion or timeout
	log.Printf("[azazel] Waiting for malware execution (max %v)...", timeout)
	
	waitCmd := exec.Command("docker", "wait", containerID)
	
	// Use a channel to wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- waitCmd.Run()
	}()

	select {
	case <-time.After(timeout):
		log.Printf("[azazel] Timeout reached. Killing container %s...", containerID)
		exec.Command("docker", "kill", containerID).Run()
	case err := <-done:
		if err != nil {
			log.Printf("[azazel] Container finished with error: %v", err)
		} else {
			log.Printf("[azazel] Container execution completed.")
		}
	}

	// Give a little time for pending events to be processed
	time.Sleep(1 * time.Second)

	// Stop tracer
	log.Println("[azazel] Stopping tracer...")
	cancel()
	t.Close()

	if !noSummary {
		writer.PrintSummary(os.Stderr)
	}

	if outputFile != "" {
		log.Printf("[azazel] Full JSON report saved to %s", outputFile)
	}

	return nil
}
