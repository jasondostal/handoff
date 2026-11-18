// handoff: send someone a link to a file or a folder. Folder links can be
// view-only or let people upload. Nothing else.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"handoff/internal/server"
	"handoff/internal/store"

	"golang.org/x/term"
)

var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "hash-password":
			os.Exit(hashPassword())
		case "version":
			fmt.Println(version)
			return
		default:
			fmt.Fprintf(os.Stderr, "usage: handoff [healthcheck | hash-password | version]\n")
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dataDir := env("HANDOFF_DATA", "/data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "handoff.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := server.Config{
		Root:              env("HANDOFF_ROOT", "/shares"),
		BaseURL:           os.Getenv("HANDOFF_BASE_URL"),
		AdminPasswordHash: os.Getenv("HANDOFF_ADMIN_PASSWORD_HASH"),
		AdminProxySecret:  os.Getenv("HANDOFF_ADMIN_PROXY_SECRET"),
		TrustProxy:        env("HANDOFF_TRUST_PROXY", "false") == "true",
		Owner:             os.Getenv("HANDOFF_OWNER"),
		Version:           version,
	}
	if pw := os.Getenv("HANDOFF_ADMIN_PASSWORD"); pw != "" && cfg.AdminPasswordHash == "" {
		if cfg.AdminPasswordHash, err = server.HashPassword(pw); err != nil {
			return err
		}
	}
	if mb := os.Getenv("HANDOFF_DEFAULT_UPLOAD_MB"); mb != "" {
		n, err := strconv.ParseInt(mb, 10, 64)
		if err != nil {
			return fmt.Errorf("HANDOFF_DEFAULT_UPLOAD_MB: %w", err)
		}
		cfg.DefaultUploadLimit = n << 20
	}
	srv, err := server.New(cfg, st, log)
	if err != nil {
		return err
	}
	defer srv.Close()

	hs := &http.Server{
		Addr:              env("HANDOFF_LISTEN", ":8080"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No read/write timeout: big uploads and zips over slow links are
		// the whole point.
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	log.Info("handoff listening", "addr", hs.Addr, "root", cfg.Root, "base", cfg.BaseURL, "version", version,
		"password_login", cfg.AdminPasswordHash != "", "proxy_auth", cfg.AdminProxySecret != "")
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func healthcheck() int {
	addr := env("HANDOFF_LISTEN", ":8080")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func hashPassword() int {
	fmt.Fprint(os.Stderr, "Password: ")
	var pw []byte
	var err error
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		var s string
		_, err = fmt.Fscanln(os.Stdin, &s)
		pw = []byte(s)
	}
	if err != nil || len(pw) == 0 {
		fmt.Fprintln(os.Stderr, "no password read")
		return 1
	}
	h, err := server.HashPassword(string(pw))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(h)
	return 0
}
