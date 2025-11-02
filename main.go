package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"wireguard-exporter-go/config"
	"wireguard-exporter-go/wireguard"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	level := slog.LevelInfo // Default log level
	varslogLevel := os.Getenv("LOG_LEVEL")
	if varslogLevel == "debug" {
		level = slog.LevelDebug
	}
	slog.Info("Log level", "level", level)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	collector := wireguard.NewCollector(cfg)

	if err := prometheus.Register(collector); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			// If already registered, unregister and re-register
			prometheus.Unregister(are.ExistingCollector)
			prometheus.Register(collector)
		} else {
			slog.Error("Failed to register collector", "error", err)
			os.Exit(1)
		}
	}

	mux := http.NewServeMux()

	mux.Handle(cfg.MetricsPath, promhttp.Handler())

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "WireGuard Prometheus Exporter\n")
		fmt.Fprintf(w, "Metrics endpoint: %s\n", cfg.MetricsPath)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	})

	server := &http.Server{
		Addr:         cfg.ListenAddress,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		slog.Info("Starting WireGuard Prometheus exporter", "address", cfg.ListenAddress, "path", cfg.MetricsPath)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server exited")
}

