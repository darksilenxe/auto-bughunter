package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"auto-bughunter/backend/internal/agentlearner"
	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/api"
	"auto-bughunter/backend/internal/graphdb"
	"auto-bughunter/backend/internal/knowledge"
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/oast"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/storage"
	"auto-bughunter/backend/internal/wordlist"
)

func main() {
	port := getenv("PORT", "8080")
	proxyPort := getenv("PROXY_PORT", "8081")
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

	attackGraphStore, err := graphdb.NewNeo4jStore(context.Background())
	if err != nil {
		log.Fatalf("neo4j init failed: %v", err)
	}
	if attackGraphStore != nil {
		defer func() {
			_ = attackGraphStore.Close(context.Background())
		}()
	}

	scanService := scanner.NewService(scanner.Config{
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
	aiClient.ConfigureCodingModel(
		getenv("AI_CODING_API_BASE", ""),
		getenv("AI_CODING_API_KEY", ""),
		getenv("AI_CODING_MODEL", "codellama"),
	)
	mlService := ml.NewService(ml.Config{
		PseudonymSalt: getenv("ML_PSEUDONYM_SALT", "auto-bughunter"),
		AuthToken:     os.Getenv("SIDECAR_AUTH_TOKEN"),
	})
	knowledgeClient := knowledge.NewClient(knowledge.Config{
		ExternalURL: os.Getenv("KNOWLEDGE_SERVICE_URL"),
		AuthToken:   os.Getenv("SIDECAR_AUTH_TOKEN"),
	})
	agentLearnerClient := agentlearner.NewClientWithToken(
		os.Getenv("AGENT_LEARNER_URL"),
		os.Getenv("SIDECAR_AUTH_TOKEN"),
	)

	// Optional self-hosted OAST (out-of-band) callback service. When enabled,
	// scanners can request a callback URL and detect blind/out-of-band
	// vulnerabilities (e.g. SSRF) by observing inbound interactions.
	var oastSvc *oast.Service
	if getbool("ENABLE_OAST", false) {
		oastSvc = oast.NewService(oast.Config{
			PublicBaseURL:   strings.TrimSpace(os.Getenv("OAST_PUBLIC_BASE_URL")),
			TTL:             time.Duration(getint("OAST_TOKEN_TTL_MINUTES", 60)) * time.Minute,
			MaxBodyBytes:    int64(getint("OAST_MAX_BODY_BYTES", 4096)),
			MaxHitsPerToken: getint("OAST_MAX_HITS_PER_TOKEN", 25),
		})
		scanService.SetOAST(oastSvc)
		oastAddr := ":" + getenv("OAST_LISTEN_PORT", "9000")
		oastHttpServer := &http.Server{
			Addr:              oastAddr,
			Handler:           oastSvc.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			pub := oastSvc.PublicBaseURL()
			if pub == "" {
				log.Printf("OAST listener on %s — WARNING: OAST_PUBLIC_BASE_URL is unset; issued tokens will have empty callback URLs", oastAddr)
			} else {
				log.Printf("OAST listener on %s (public base %s)", oastAddr, pub)
			}
			if err := oastHttpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("oast listener error: %v", err)
			}
		}()
	}

	server := api.NewServer(
		scanService,
		aiClient,
		mlService,
		knowledgeClient,
		agentLearnerClient,
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
	if oastSvc != nil {
		server.SetOAST(oastSvc)
	}
	if attackGraphStore != nil {
		server.SetAttackGraphStore(attackGraphStore)
	}

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start the intercepting proxy listener if enabled.
	if getbool("ENABLE_PROXY", false) {
		proxyHandler := proxy.NewServer(repo)
		proxyHttpServer := &http.Server{
			Addr:              ":" + proxyPort,
			Handler:           proxyHandler,
			ReadHeaderTimeout: 30 * time.Second,
		}
		go func() {
			log.Printf("intercepting proxy listening on :%s — configure your browser/tool to use localhost:%s as HTTP proxy", proxyPort, proxyPort)
			if err := proxyHttpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("proxy server error: %v", err)
			}
		}()
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
