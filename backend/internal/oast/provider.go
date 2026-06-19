package oast

import "time"

// Provider is the interface satisfied by both *Service (self-hosted OAST
// listener) and *interactsh.Client (public interactsh infrastructure). Any
// scanner or agent that needs out-of-band callbacks depends on this interface
// rather than a concrete type so the two back-ends are interchangeable.
type Provider interface {
	// Configured reports whether the provider has a public base URL and is
	// ready to issue usable callback URLs.
	Configured() bool

	// Issue creates a new interaction token associated with the given scan ID
	// and label. Either may be empty. The returned Token's CallbackURL is
	// the externally reachable URL to embed in payloads.
	Issue(scanID, label string) Token

	// Hits returns a copy of all interactions recorded for a token. The
	// boolean reports whether the token is known (and unexpired).
	Hits(token string) ([]Hit, bool)

	// Wait blocks until the token records at least one interaction, the
	// timeout elapses, or the context is cancelled. Returns all hits so far.
	// An unknown token returns immediately with a nil slice.
	Wait(token string, timeout time.Duration) []Hit

	// Tokens returns metadata for every active token, optionally filtered by
	// scanID. Pass an empty string to list all active tokens.
	Tokens(scanID string) []Token

	// PublicBaseURL returns the base URL prefix used when constructing
	// callback URLs (e.g. "http://oast.example.com:9000" or
	// "https://oast.pro").
	PublicBaseURL() string
}
