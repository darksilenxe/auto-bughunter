package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/agentlearner"
	"auto-bughunter/backend/internal/api"
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/storage"
	"auto-bughunter/backend/internal/wordlist"
)

func main() {
	port := getenv("PORT", "8080")
	proxyPort := getenv("PROXY_PORT", "8081")
	allowed := splitCSV(os.Getenv("ALLOWED_TARGETS"))
	databaseURL := getenv("DATABASE_URL", "postgres://auto:auto@db:5432/autobughunter?sslmode=disable")

	// Validate configuration up-front so misconfigurations surface as a
	// clear error rather than as runtime failures hours later.
	if err := validateConfig(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	enableSecLists := getbool("ENABLE_SECLISTS_WORDLISTS", true)
	enableKiterunner := getbool("ENABLE_KITERUNNER_WORDLISTS", true)
	wordlist.InitLoader(enableSecLists, enableKiterunner)

	repo, err := storage.NewPostgres(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("postgres init failed: %v", err)
	}
	defer func() {
		_ = repo.Close()
	}()

	scanService := scanner.NewService(scanner.Config{
		EnableNuclei:       getbool("ENABLE_NUCLEI_INTEGRATION", false),
		EnableZAPBaseline:  getbool("ENABLE_ZAP_BASELINE_INTEGRATION", false),
		EnableSubfinder:    getbool("ENABLE_SUBFINDER_INTEGRATION", false),
		EnableHttpx:        getbool("ENABLE_HTTPX_INTEGRATION", false),
		EnableNaabu:        getbool("ENABLE_NAABU_INTEGRATION", false),
		EnableDnsx:         getbool("ENABLE_DNSX_INTEGRATION", false),
		EnableShuffleDNS:   getbool("ENABLE_SHUFFLEDNS_INTEGRATION", false),
		EnableCertTrans:    getbool("ENABLE_CERTIFICATE_TRANSPARENCY_INTEGRATION", false),
		EnableAmass:        getbool("ENABLE_AMASS_INTEGRATION", false),
		EnableKatana:       getbool("ENABLE_KATANA_INTEGRATION", false),
		EnableTlsx:         getbool("ENABLE_TLSX_INTEGRATION", false),
		EnableCdncheck:     getbool("ENABLE_CDNCHECK_INTEGRATION", false),
		EnableAsnmap:       getbool("ENABLE_ASNMAP_INTEGRATION", false),
		EnableNikto:        getbool("ENABLE_NIKTO_INTEGRATION", false),
		EnableWPScan:       getbool("ENABLE_WPSCAN_INTEGRATION", false),
		EnableSQLMap:       getbool("ENABLE_SQLMAP_INTEGRATION", false),
		EnableFFUF:         getbool("ENABLE_FFUF_INTEGRATION", false),
		EnableGobuster:     getbool("ENABLE_GOBUSTER_INTEGRATION", false),
		AllowDestructive:   getbool("ALLOW_DESTRUCTIVE_CHECKS", false),
		NucleiBinary:       getenv("NUCLEI_BINARY", "nuclei"),
		ZAPBaselineBinary:  getenv("ZAP_BASELINE_BINARY", "zap-baseline.py"),
		SubfinderBinary:    getenv("SUBFINDER_BINARY", "subfinder"),
		HttpxBinary:        getenv("HTTPX_BINARY", "httpx"),
		NaabuBinary:        getenv("NAABU_BINARY", "naabu"),
		DnsxBinary:         getenv("DNSX_BINARY", "dnsx"),
		ShuffleDNSBinary:   getenv("SHUFFLEDNS_BINARY", "shuffledns"),
		KatanaBinary:       getenv("KATANA_BINARY", "katana"),
		TlsxBinary:         getenv("TLSX_BINARY", "tlsx"),
		CdncheckBinary:     getenv("CDNCHECK_BINARY", "cdncheck"),
		AsnmapBinary:       getenv("ASNMAP_BINARY", "asnmap"),
		FFUFBinary:         getenv("FFUF_BINARY", "ffuf"),
		GobusterBinary:     getenv("GOBUSTER_BINARY", "gobuster"),
		IntegrationTimeout: time.Duration(getint("INTEGRATION_TIMEOUT_SECONDS", 90)) * time.Second,
		DefaultMaxRetries:  getint("DEFAULT_MAX_RETRIES", 1),
		DefaultBackoff:     time.Duration(getint("DEFAULT_BACKOFF_MILLIS", 400)) * time.Millisecond,
	})
	aiClient := ai.NewClient(
		os.Getenv("AI_API_BASE"),
		os.Getenv("AI_API_KEY"),
		os.Getenv("AI_MODEL"),
	)
	mlService := ml.NewService(ml.Config{
		PseudonymSalt: getenv("ML_PSEUDONYM_SALT", "auto-bughunter"),
	})
	agentLearnerClient := agentlearner.NewClient(os.Getenv("AGENT_LEARNER_URL"))

	server := api.NewServer(
		scanService,
		aiClient,
		mlService,
		agentLearnerClient,
		allowed,
		repo,
		repo,
		getint("MAX_PER_TARGET_CONCURRENCY", 3),
		getint("GLOBAL_SCAN_BUDGET", 5),
		api.AgentConfig{
			EnableMLTriageAgent:      getbool("ENABLE_ML_TRIAGE_AGENT", true),
			EnableAttackPathAgent:    getbool("ENABLE_ATTACK_PATH_AGENT", true),
			EnableFalsePositiveAgent: getbool("ENABLE_FALSE_POSITIVE_REVIEW_AGENT", true),
			EnableRemediationAgent:   getbool("ENABLE_REMEDIATION_PLANNER_AGENT", true),
		},
		time.Duration(getint("SCAN_TIMEOUT_SECONDS", 600))*time.Second,
	)

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start the intercepting proxy listener if enabled.
	var proxyHttpServer *http.Server
	if getbool("ENABLE_PROXY", false) {
		proxyHandler := proxy.NewServer(repo)
		proxyHttpServer = &http.Server{
			Addr:              ":" + proxyPort,
			Handler:           proxyHandler,
			ReadHeaderTimeout: 30 * time.Second,
		}
		go func() {
			log.Printf("intercepting proxy listening on :%s — configure your browser/tool to use localhost:%s as HTTP proxy", proxyPort, proxyPort)
			if err := proxyHttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("proxy server error: %v", err)
			}
		}()
	}

	// Listen for SIGINT/SIGTERM to perform a graceful shutdown of both
	// HTTP listeners. In-flight requests are given a bounded grace period
	// (SHUTDOWN_GRACE_SECONDS, default 30) before the process exits.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("backend listening on :%s", port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case sig := <-stop:
		log.Printf("received %s, shutting down gracefully", sig)
	case err := <-serverErr:
		log.Fatalf("server error: %v", err)
	}

	grace := time.Duration(getint("SHUTDOWN_GRACE_SECONDS", 30)) * time.Second
	shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	if proxyHttpServer != nil {
		if err := proxyHttpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("proxy graceful shutdown failed: %v", err)
		}
	}
	log.Printf("shutdown complete")
}

// validateConfig sanity-checks numeric/range environment variables and
// returns a descriptive error explaining the first problem found. It runs
// before any expensive initialisation (DB connection, Chrome launch, …)
// so misconfigurations fail fast.
func validateConfig() error {
	intRanges := []struct {
		key      string
		min, max int
	}{
		{"PORT", 1, 65535},
		{"PROXY_PORT", 1, 65535},
		{"INTEGRATION_TIMEOUT_SECONDS", 1, 86400},
		{"SCAN_TIMEOUT_SECONDS", 1, 86400},
		{"DEFAULT_MAX_RETRIES", 0, 100},
		{"DEFAULT_BACKOFF_MILLIS", 0, 600000},
		{"MAX_PER_TARGET_CONCURRENCY", 1, 1000},
		{"GLOBAL_SCAN_BUDGET", 1, 10000},
		{"API_RATE_LIMIT_PER_MINUTE", 0, 1_000_000},
		{"SHUTDOWN_GRACE_SECONDS", 1, 600},
	}
	for _, r := range intRanges {
		v := strings.TrimSpace(os.Getenv(r.key))
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return errors.New(r.key + " must be an integer (got " + v + ")")
		}
		if n < r.min || n > r.max {
			return errors.New(r.key + " out of range [" + strconv.Itoa(r.min) + "," + strconv.Itoa(r.max) + "] (got " + v + ")")
		}
	}
	if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); v != "" {
		u, err := url.Parse(v)
		if err != nil {
			return errors.New("DATABASE_URL is not a valid URL: " + err.Error())
		}
		if u.Scheme != "postgres" && u.Scheme != "postgresql" {
			return errors.New("DATABASE_URL must use postgres:// or postgresql:// scheme (got " + u.Scheme + ")")
		}
		if u.Host == "" {
			return errors.New("DATABASE_URL must include a host")
		}
	}
	return nil
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getbool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getint(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
