// Package interactsh provides a lightweight client for the projectdiscovery
// interactsh out-of-band interaction server (https://github.com/projectdiscovery/interactsh).
//
// The client registers with a public or self-hosted interactsh server, obtains
// a correlation ID that is used as a subdomain prefix, and pre-allocates a
// pool of unique callback URLs (one per probe). Each URL has the form:
//
//	http://<correlationID><randomSuffix>.<serverHost>
//
// The server captures HTTP, DNS, and SMTP interactions for any URL matching
// the registered correlation ID. The client polls periodically and records
// interactions so scanners can call Wait/Hits to check for callbacks.
//
// The client implements oast.Provider and is a drop-in replacement for the
// self-hosted *oast.Service when a public interactsh server is preferred.
package interactsh

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/oast"
)

const (
	// DefaultServerURL is the public interactsh server used when none is configured.
	DefaultServerURL = "https://oast.pro"

	correlationIDLen = 20
	randomSuffixLen  = 13
	defaultTTL       = time.Hour
	defaultPollInterval = 5 * time.Second
)

// Config configures a Client.
type Config struct {
	// ServerURL is the interactsh server base URL.
	// Defaults to DefaultServerURL ("https://oast.pro").
	ServerURL string

	// Token is an optional API bearer token sent in every request to a
	// protected server (e.g. a self-hosted instance with auth enabled).
	Token string

	// PollInterval is how often the client polls for new interactions.
	// Defaults to 5 s.
	PollInterval time.Duration

	// TTL is how long issued tokens (and their interactions) are retained
	// in memory. Defaults to 1 h.
	TTL time.Duration
}

// interaction is the JSON payload decrypted from a poll response entry.
type interaction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	RawRequest    string    `json:"raw-request"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
	QType         string    `json:"q-type"` // DNS query type, e.g. "A"
}

// pollResponse is the JSON body returned by GET /poll.
type pollResponse struct {
	Data   []string `json:"data"`
	Extra  []string `json:"extra"`
	AESKey string   `json:"aes_key"`
}

type registerBody struct {
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

type tokenState struct {
	meta   oast.Token
	hits   []oast.Hit
	signal chan struct{}
}

// Client is an interactsh HTTP client. It implements oast.Provider so it can
// be used wherever a *oast.Service is expected.
type Client struct {
	cfg           Config
	serverURL     string // trimmed, no trailing slash
	serverHost    string // host portion only, e.g. "oast.pro"
	correlationID string
	secretKey     string
	rsaKey        *rsa.PrivateKey
	httpClient    *http.Client

	mu     sync.RWMutex
	aesKey []byte // decrypted from first poll response with data
	tokens map[string]*tokenState
	now    func() time.Time // overridable in tests
}

// New creates a new Client. Call Start to register and begin polling.
// New does not make any network requests.
func New(cfg Config) (*Client, error) {
	if cfg.ServerURL == "" {
		cfg.ServerURL = DefaultServerURL
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("interactsh: generate RSA key: %w", err)
	}

	corrID, err := randomAlphanumeric(correlationIDLen)
	if err != nil {
		return nil, fmt.Errorf("interactsh: generate correlation ID: %w", err)
	}

	secret, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("interactsh: generate secret key: %w", err)
	}

	serverURL := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	serverHost := serverURL
	for _, pfx := range []string{"https://", "http://"} {
		serverHost = strings.TrimPrefix(serverHost, pfx)
	}

	return &Client{
		cfg:           cfg,
		serverURL:     serverURL,
		serverHost:    serverHost,
		correlationID: corrID,
		secretKey:     secret,
		rsaKey:        rsaKey,
		tokens:        make(map[string]*tokenState),
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		now:           time.Now,
	}, nil
}

// Start registers with the interactsh server and launches a background polling
// goroutine. The goroutine runs until ctx is cancelled, at which point it
// deregisters from the server. Start should be called once after New.
func (c *Client) Start(ctx context.Context) error {
	if err := c.register(ctx); err != nil {
		return err
	}
	go c.pollLoop(ctx)
	return nil
}

// PreAllocate issues n interaction tokens and returns their callback URLs.
// This creates the "list of domains" that agents use for OAST callbacks:
// each URL can be embedded in a probe payload (HTTP header, XML entity,
// command-injection string, etc.) and any DNS or HTTP interaction with it
// will be recorded. PreAllocate must be called after Start.
func (c *Client) PreAllocate(n int) []string {
	urls := make([]string, 0, n)
	for i := 0; i < n; i++ {
		tok := c.Issue("", "preallocated")
		if tok.CallbackURL != "" {
			urls = append(urls, tok.CallbackURL)
		}
	}
	return urls
}

// — oast.Provider interface —

// Configured reports true; the client always has a server URL.
func (c *Client) Configured() bool { return c.serverURL != "" }

// Issue creates a new interaction token with a unique callback URL. The URL is
// of the form "http://<correlationID><13-char-random>.<serverHost>". Any DNS
// query or HTTP request to this domain is captured by the server and surfaced
// via Hits/Wait.
func (c *Client) Issue(scanID, label string) oast.Token {
	suffix, err := randomAlphanumeric(randomSuffixLen)
	if err != nil {
		suffix = strings.Repeat("a", randomSuffixLen) // extremely rare fallback
	}
	uniqueID := c.correlationID + suffix
	callbackURL := "http://" + uniqueID + "." + c.serverHost

	now := c.now()
	meta := oast.Token{
		Token:       uniqueID,
		CallbackURL: callbackURL,
		ScanID:      scanID,
		Label:       label,
		IssuedAt:    now,
		ExpiresAt:   now.Add(c.cfg.TTL),
	}

	c.mu.Lock()
	c.tokens[uniqueID] = &tokenState{
		meta:   meta,
		signal: make(chan struct{}),
	}
	c.mu.Unlock()

	return meta
}

// Hits returns a copy of all recorded interactions for the token. The boolean
// is false when the token is unknown or expired.
func (c *Client) Hits(token string) ([]oast.Hit, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st, ok := c.tokens[token]
	if !ok || c.now().After(st.meta.ExpiresAt) {
		return nil, false
	}
	out := make([]oast.Hit, len(st.hits))
	copy(out, st.hits)
	return out, true
}

// Wait blocks until token records at least one interaction, the timeout
// elapses, or the context is cancelled. Returns all hits recorded so far.
func (c *Client) Wait(token string, timeout time.Duration) []oast.Hit {
	c.mu.RLock()
	st, ok := c.tokens[token]
	if !ok {
		c.mu.RUnlock()
		return nil
	}
	if len(st.hits) > 0 {
		out := make([]oast.Hit, len(st.hits))
		copy(out, st.hits)
		c.mu.RUnlock()
		return out
	}
	signal := st.signal
	c.mu.RUnlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-signal:
	case <-timer.C:
	}
	hits, _ := c.Hits(token)
	return hits
}

// Tokens returns metadata for all active tokens, optionally filtered by scanID.
func (c *Client) Tokens(scanID string) []oast.Token {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now()
	out := make([]oast.Token, 0, len(c.tokens))
	for _, st := range c.tokens {
		if now.After(st.meta.ExpiresAt) {
			continue
		}
		if scanID != "" && st.meta.ScanID != scanID {
			continue
		}
		out = append(out, st.meta)
	}
	return out
}

// PublicBaseURL returns the interactsh server URL (e.g. "https://oast.pro").
func (c *Client) PublicBaseURL() string { return c.serverURL }

// — internal helpers —

func (c *Client) register(ctx context.Context) error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&c.rsaKey.PublicKey)
	if err != nil {
		return fmt.Errorf("interactsh: marshal public key: %w", err)
	}
	body, err := json.Marshal(registerBody{
		PublicKey:     base64.StdEncoding.EncodeToString(pubKeyBytes),
		SecretKey:     c.secretKey,
		CorrelationID: c.correlationID,
	})
	if err != nil {
		return fmt.Errorf("interactsh: marshal register request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("interactsh: new register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("interactsh: register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("interactsh: register: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *Client) deregister() {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&c.rsaKey.PublicKey)
	if err != nil {
		return
	}
	body, err := json.Marshal(registerBody{
		PublicKey:     base64.StdEncoding.EncodeToString(pubKeyBytes),
		SecretKey:     c.secretKey,
		CorrelationID: c.correlationID,
	})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, c.serverURL+"/deregister", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (c *Client) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.PollInterval)
	defer func() {
		ticker.Stop()
		c.deregister()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

func (c *Client) poll(ctx context.Context) {
	url := fmt.Sprintf("%s/poll?id=%s&secret=%s", c.serverURL, c.correlationID, c.secretKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	var pr pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return
	}
	if len(pr.Data) == 0 && len(pr.Extra) == 0 {
		return
	}

	// Decrypt or update the AES key whenever the server includes it.
	if pr.AESKey != "" {
		if decoded, err := base64.StdEncoding.DecodeString(pr.AESKey); err == nil {
			if key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.rsaKey, decoded, nil); err == nil {
				c.mu.Lock()
				c.aesKey = key
				c.mu.Unlock()
			}
		}
	}

	c.mu.RLock()
	aesKey := c.aesKey
	c.mu.RUnlock()
	if aesKey == nil {
		return
	}

	for _, enc := range append(pr.Data, pr.Extra...) {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			continue
		}
		plain, err := aesDecrypt(aesKey, raw)
		if err != nil {
			continue
		}
		var ia interaction
		if err := json.Unmarshal(plain, &ia); err != nil {
			continue
		}
		c.recordInteraction(ia)
	}
}

func (c *Client) recordInteraction(ia interaction) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.tokens[ia.UniqueID]
	if !ok {
		// Interaction arrived for a URL we issued but whose state may have
		// been evicted, or for a URL not issued through Issue() (rare).
		// Only accept interactions whose unique ID starts with our correlation
		// ID (i.e. came from a URL we issued).
		if !strings.HasPrefix(ia.UniqueID, c.correlationID) {
			return
		}
		now := c.now()
		st = &tokenState{
			meta: oast.Token{
				Token:     ia.UniqueID,
				IssuedAt:  now,
				ExpiresAt: now.Add(c.cfg.TTL),
			},
			signal: make(chan struct{}),
		}
		c.tokens[ia.UniqueID] = st
	}

	// Map interactsh protocol to an HTTP-method-like field so the existing
	// oast.Hit model can carry DNS and SMTP interactions:
	//   HTTP  -> the actual HTTP method (GET, POST, …)
	//   DNS   -> "DNS" with path "/<query-type>"
	//   SMTP  -> "SMTP"
	method := strings.ToUpper(ia.Protocol)
	if method == "" {
		method = "HTTP"
	}
	path := "/"
	if ia.QType != "" {
		path = "/" + strings.ToUpper(ia.QType)
	}

	ts := ia.Timestamp
	if ts.IsZero() {
		ts = c.now()
	}

	hit := oast.Hit{
		Token:      ia.UniqueID,
		Method:     method,
		Path:       path,
		RemoteAddr: ia.RemoteAddress,
		Body:       truncate(ia.RawRequest, 4096),
		ReceivedAt: ts,
	}

	st.hits = append(st.hits, hit)
	// Broadcast to any goroutine blocked in Wait.
	old := st.signal
	st.signal = make(chan struct{})
	close(old)
}

// aesDecrypt decrypts cipherText using AES-256-CFB. The first aes.BlockSize
// bytes of cipherText are the IV (as produced by the interactsh server).
func aesDecrypt(key, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("interactsh: ciphertext too short (%d bytes)", len(cipherText))
	}
	iv := cipherText[:aes.BlockSize]
	data := make([]byte, len(cipherText)-aes.BlockSize)
	copy(data, cipherText[aes.BlockSize:])
	// The interactsh server encrypts payloads with AES-256-CFB. We must match
	// this mode for protocol compatibility; switching to a different stream
	// cipher would break decryption of server responses.
	//lint:ignore SA1019 cipher.NewCFBDecrypter is required by the interactsh wire protocol
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

// randomAlphanumeric returns a random lowercase alphanumeric string of length n
// using crypto/rand for uniformity.
func randomAlphanumeric(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	// Generate candidate bytes, retaining only those that fall below the
	// largest multiple of len(alphabet) ≤ 256 to avoid modulo bias.
	limit := byte(256 - 256%len(alphabet))
	out := make([]byte, 0, n)
	buf := make([]byte, n*2) // over-provision to avoid repeated reads
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if len(out) >= n {
				break
			}
			if b < limit {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}

// randomHex returns a cryptographically random hex string of n bytes (2n chars).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
