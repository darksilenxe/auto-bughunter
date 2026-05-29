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
	"auto-bughunter/backend/internal/memory"
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/oast"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/secureurl"
	"auto-bughunter/backend/internal/storage"
	"auto-bughunter/backend/internal/wordlist"
)

func main() {
	port := getenv("PORT", "8080")
	proxyPort := getenv("PROXY_PORT", "8081")
	databaseURL := getenv("DATABASE_URL", "postgres://auto:auto@db:5432/autobughunter?sslmode=disable")

	// Enforce HTTPS (or private-network HTTP) for all env-configured outbound
	// endpoints. This guards against accidentally pointing the backend at a
	// cleartext public-internet service such as `http://api.openai.com`.
	// Set ALLOW_INSECURE_OUTBOUND_URLS=true to bypass.
	//
	// NOTE: This does NOT constrain scan-target URLs, OAST callbacks, or
	// any scanner-issued requests — those must remain protocol-agnostic.
	if err := secureurl.ValidateMany(map[string]string{
		"AI_API_BASE":           os.Getenv("AI_API_BASE"),
		"AI_CODING_API_BASE":    os.Getenv("AI_CODING_API_BASE"),
		"KNOWLEDGE_SERVICE_URL": os.Getenv("KNOWLEDGE_SERVICE_URL"),
		"AGENT_LEARNER_URL":     os.Getenv("AGENT_LEARNER_URL"),
		"ML_SERVICE_URL":        os.Getenv("ML_SERVICE_URL"),
		"NUCLEI_SERVICE_URL":    os.Getenv("NUCLEI_SERVICE_URL"),
		"ZAP_SERVICE_URL":       os.Getenv("ZAP_SERVICE_URL"),
		"BURP_API_URL":          os.Getenv("BURP_API_URL"),
		"MSF_RPC_URL":           os.Getenv("MSF_RPC_URL"),
		"CHROME_REMOTE_URL":     os.Getenv("CHROME_REMOTE_URL"),
		"XSSMAP_OLLAMA_URL":     os.Getenv("XSSMAP_OLLAMA_URL"),
	}, getbool("ALLOW_INSECURE_OUTBOUND_URLS", false)); err != nil {
		log.Fatalf("insecure outbound URL configuration: %v", err)
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
		EnableCloudlist:    getbool("ENABLE_CLOUDLIST_INTEGRATION", false),
		EnableVulnx:        getbool("ENABLE_VULNX_INTEGRATION", false),
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
		XSSMapBinary:       getenv("XSSMAP_BINARY", "xssmap"),
		SubfinderBinary:    getenv("SUBFINDER_BINARY", "subfinder"),
		HttpxBinary:        getenv("HTTPX_BINARY", "httpx"),
		CloudlistBinary:    getenv("CLOUDLIST_BINARY", "cloudlist"),
		VulnxBinary:        getenv("VULNX_BINARY", "vulnx"),
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
	// Optional upstream proxy for scanner-initiated HTTP traffic. When
	// SCANNER_USE_PROXY=true, all probes are routed through SCANNER_PROXY_URL
	// (default http://127.0.0.1:${PROXY_PORT}, i.e. the bundled MITM proxy).
	// Set SCANNER_PROXY_URL to point at an external proxy such as Burp/ZAP.
	scannerProxyCfg := scanner.ProxyConfig{
		Enabled:            getbool("SCANNER_USE_PROXY", false),
		URL:                getenv("SCANNER_PROXY_URL", "http://127.0.0.1:"+proxyPort),
		CAFile:             strings.TrimSpace(os.Getenv("SCANNER_PROXY_CA_FILE")),
		InsecureSkipVerify: getbool("SCANNER_PROXY_INSECURE_SKIP_VERIFY", false),
	}
	if scannerProxyCfg.Enabled {
		if err := scanService.SetScannerProxy(scannerProxyCfg, proxyPort); err != nil {
			log.Printf("scanner upstream proxy disabled: %v — scans will use direct connections", err)
		} else {
			log.Printf("scanner upstream proxy enabled — outbound probes route via %s", scannerProxyCfg.URL)
			if !getbool("ENABLE_PROXY", false) && scannerProxyCfg.IsBundledLocal(proxyPort) {
				log.Printf("WARNING: SCANNER_PROXY_URL=%s targets the bundled proxy port :%s but ENABLE_PROXY=false — outbound requests will fail until ENABLE_PROXY is set", scannerProxyCfg.URL, proxyPort)
			}
		}
	}
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

	// Optional episodic vector memory.  When ENABLE_VECTOR_MEMORY=true (and
	// pgvector is available in the database), confirmed findings are embedded
	// and stored for cross-scan hypothesis enrichment.  Falls back to the
	// in-process local store when the pgvector extension cannot be loaded.
	if getbool("ENABLE_VECTOR_MEMORY", false) {
		memDSN := getenv("VECTOR_MEMORY_DSN", databaseURL)
		pvStore, pvErr := memory.NewPgvectorStore(context.Background(), memDSN)
		if pvErr != nil {
			log.Printf("pgvector memory unavailable (%v) — falling back to in-process local store", pvErr)
			localMem := memory.NewLocalStore()
			server.SetVectorMemory(&localMemoryAdapter{localMem})
		} else {
			log.Printf("pgvector episodic memory initialised (DSN=%s)", maskDSN(memDSN))
			server.SetVectorMemory(&pgvectorMemoryAdapter{pvStore})
			defer func() {
				_ = pvStore.Close()
			}()
		}
	}

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start the intercepting proxy listener if enabled.
	if getbool("ENABLE_PROXY", false) {
		// Optional self-signed CA bootstrap. When PROXY_CA_CERT_FILE +
		// PROXY_CA_KEY_FILE are set, HTTPS CONNECT tunnels are
		// intercepted ("MITM") and full request/response bodies are
		// captured. With PROXY_CA_AUTOGENERATE=true the CA is created
		// on first boot if the files don't exist.
		var ca *proxy.CA
		caCert := strings.TrimSpace(os.Getenv("PROXY_CA_CERT_FILE"))
		caKey := strings.TrimSpace(os.Getenv("PROXY_CA_KEY_FILE"))
		if caCert != "" && caKey != "" {
			loaded, err := proxy.LoadOrGenerateCA(proxy.CAOptions{
				CertFile:     caCert,
				KeyFile:      caKey,
				AutoGenerate: getbool("PROXY_CA_AUTOGENERATE", false),
				CommonName:   getenv("PROXY_CA_COMMON_NAME", ""),
			})
			if err != nil {
				log.Printf("proxy CA bootstrap failed: %v — HTTPS interception disabled", err)
			} else if loaded != nil {
				ca = loaded
				log.Printf("proxy CA loaded (fingerprint %s, expires %s)", ca.Fingerprint(), ca.NotAfter().UTC().Format(time.RFC3339))
			}
		}
		proxyHandler := proxy.NewServerWithCA(repo, ca)
		server.SetProxyServer(proxyHandler)
		proxyHttpServer := &http.Server{
			Addr:              ":" + proxyPort,
			Handler:           proxyHandler,
			ReadHeaderTimeout: 30 * time.Second,
		}
		go func() {
			mode := "transparent (HTTPS bodies not captured)"
			if ca != nil {
				mode = "TLS-intercepting (install CA via /api/proxy/ca-certificate)"
			}
			log.Printf("intercepting proxy listening on :%s — %s — configure your browser to use localhost:%s as HTTP proxy", proxyPort, mode, proxyPort)
			log.Printf("browser proxy integration active — all headless browser requests during scanning will route through the proxy")
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

// ---------------------------------------------------------------------------
// Vector memory adapters bridge memory.Store → api.vectorMemoryStore without
// creating an interface cycle.  The api package defines vectorMemoryFinding;
// these adapters translate to/from the canonical memory.FindingMemory.
// ---------------------------------------------------------------------------

type pgvectorMemoryAdapter struct{ s *memory.PgvectorStore }

func (a *pgvectorMemoryAdapter) UpsertFinding(ctx context.Context, f api.VectorMemoryFinding) error {
	return a.s.UpsertFinding(ctx, memory.FindingMemory{
		ID: f.ID, Target: f.Target, ScanID: f.ScanID, Category: f.Category,
		Title: f.Title, Severity: f.Severity, Embedding: f.Embedding,
	})
}

func (a *pgvectorMemoryAdapter) SearchByTarget(ctx context.Context, target string, topK int) ([]api.VectorMemoryFinding, error) {
	rows, err := a.s.SearchByTarget(ctx, target, topK)
	if err != nil {
		return nil, err
	}
	out := make([]api.VectorMemoryFinding, len(rows))
	for i, r := range rows {
		out[i] = api.VectorMemoryFinding{
			ID: r.ID, Target: r.Target, ScanID: r.ScanID, Category: r.Category,
			Title: r.Title, Severity: r.Severity, Embedding: r.Embedding,
		}
	}
	return out, nil
}
func (a *pgvectorMemoryAdapter) Close() error { return a.s.Close() }

type localMemoryAdapter struct{ s *memory.LocalStore }

func (a *localMemoryAdapter) UpsertFinding(ctx context.Context, f api.VectorMemoryFinding) error {
	return a.s.UpsertFinding(ctx, memory.FindingMemory{
		ID: f.ID, Target: f.Target, ScanID: f.ScanID, Category: f.Category,
		Title: f.Title, Severity: f.Severity, Embedding: f.Embedding,
	})
}

func (a *localMemoryAdapter) SearchByTarget(ctx context.Context, target string, topK int) ([]api.VectorMemoryFinding, error) {
	rows, err := a.s.SearchByTarget(ctx, target, topK)
	if err != nil {
		return nil, err
	}
	out := make([]api.VectorMemoryFinding, len(rows))
	for i, r := range rows {
		out[i] = api.VectorMemoryFinding{
			ID: r.ID, Target: r.Target, ScanID: r.ScanID, Category: r.Category,
			Title: r.Title, Severity: r.Severity, Embedding: r.Embedding,
		}
	}
	return out, nil
}
func (a *localMemoryAdapter) Close() error { return a.s.Close() }

// maskDSN redacts the password from a PostgreSQL DSN for safe logging.
func maskDSN(dsn string) string {
	if idx := strings.Index(dsn, "@"); idx != -1 {
		// Replace everything before the last : before @ with ***
		prefix := dsn[:idx]
		if ci := strings.LastIndex(prefix, ":"); ci != -1 {
			return dsn[:ci+1] + "***" + dsn[idx:]
		}
	}
	return dsn
}
