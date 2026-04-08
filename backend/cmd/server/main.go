package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/api"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/storage"
	"auto-bughunter/backend/internal/wordlist"
)

func main() {
	port := getenv("PORT", "8080")
	allowed := splitCSV(os.Getenv("ALLOWED_TARGETS"))
	databaseURL := getenv("DATABASE_URL", "postgres://auto:auto@db:5432/autobughunter?sslmode=disable")

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
		EnableKatana:       getbool("ENABLE_KATANA_INTEGRATION", false),
		EnableTlsx:         getbool("ENABLE_TLSX_INTEGRATION", false),
		EnableCdncheck:     getbool("ENABLE_CDNCHECK_INTEGRATION", false),
		EnableAsnmap:       getbool("ENABLE_ASNMAP_INTEGRATION", false),
		NucleiBinary:       getenv("NUCLEI_BINARY", "nuclei"),
		ZAPBaselineBinary:  getenv("ZAP_BASELINE_BINARY", "zap-baseline.py"),
		SubfinderBinary:    getenv("SUBFINDER_BINARY", "subfinder"),
		HttpxBinary:        getenv("HTTPX_BINARY", "httpx"),
		NaabuBinary:        getenv("NAABU_BINARY", "naabu"),
		DnsxBinary:         getenv("DNSX_BINARY", "dnsx"),
		KatanaBinary:       getenv("KATANA_BINARY", "katana"),
		TlsxBinary:         getenv("TLSX_BINARY", "tlsx"),
		CdncheckBinary:     getenv("CDNCHECK_BINARY", "cdncheck"),
		AsnmapBinary:       getenv("ASNMAP_BINARY", "asnmap"),
		IntegrationTimeout: time.Duration(getint("INTEGRATION_TIMEOUT_SECONDS", 90)) * time.Second,
	})
	aiClient := ai.NewClient(
		os.Getenv("AI_API_BASE"),
		os.Getenv("AI_API_KEY"),
		os.Getenv("AI_MODEL"),
	)

	server := api.NewServer(scanService, aiClient, allowed, repo)

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("backend listening on :%s", port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
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
