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
	"github.com/blackestwhite/iqs-tunnel/internal/config"
	"github.com/blackestwhite/iqs-tunnel/internal/server"
)

func main() {
	configPath := flag.String("config", "configs/server.example.json", "path to the server config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.Version)
		return
	}

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		log.Fatalf("load server config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, cfg); err != nil {
		log.Fatalf("server exited with error: %v", err)
	}
}
