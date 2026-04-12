package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/blackestwhite/iqs-tunnel/internal/buildinfo"
	"github.com/blackestwhite/iqs-tunnel/internal/client"
	"github.com/blackestwhite/iqs-tunnel/internal/config"
)

func main() {
	configPath := flag.String("config", "configs/client.example.json", "path to the client config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.Version)
		return
	}

	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		log.Fatalf("load client config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := client.Run(ctx, cfg); err != nil {
		log.Fatalf("client exited with error: %v", err)
	}
}
