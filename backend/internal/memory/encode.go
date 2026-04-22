package memory

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

const embeddingDims = 64

// Encode produces a deterministic 64-dimensional float32 unit vector from a
// text string.  The algorithm is a random-projection sketch over bag-of-words
// tokens, which is parameter-free, reproducible, and captures semantic
// similarity through shared token overlap.
//
// Algorithm:
//  1. Tokenize: lowercase, split on non-alphanumeric characters.
//  2. For each (token, dimension) pair, compute FNV-32a(token + dim) and use
//     the parity of the hash as a +1 / −1 projection.
//  3. Sum all projections per dimension.
//  4. L2-normalize the resulting vector.
func Encode(text string) []float32 {
	tokens := tokenize(text)
	vec := make([]float64, embeddingDims)
	if len(tokens) == 0 {
		// Return a zero vector rather than dividing by zero.
		return make([]float32, embeddingDims)
	}
	for _, tok := range tokens {
		for d := 0; d < embeddingDims; d++ {
			h := fnv32a(tok + strconv.Itoa(d))
			if h%2 == 0 {
				vec[d] += 1.0
			} else {
				vec[d] -= 1.0
			}
		}
	}
	return l2Normalize(vec)
}

// EncodeMulti encodes multiple strings by concatenating them with a space
// separator before encoding.
func EncodeMulti(parts ...string) []float32 {
	return Encode(strings.Join(parts, " "))
}

// CosineSimilarity computes the cosine similarity between two float32 vectors
// of equal length.  Returns 0 when either vector is zero-length or lengths
// differ.
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(normA) * math.Sqrt(normB)))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

var tokenSplitter = regexp.MustCompile(`[^a-z0-9]+`)

func tokenize(text string) []string {
	lower := strings.ToLower(text)
	parts := tokenSplitter.Split(lower, -1)
	out := parts[:0]
	for _, p := range parts {
		if len(p) >= 2 {
			out = append(out, p)
		}
	}
	return out
}

func l2Normalize(vec []float64) []float32 {
	var sum float64
	for _, v := range vec {
		sum += v * v
	}
	if sum == 0 {
		out := make([]float32, len(vec))
		return out
	}
	norm := math.Sqrt(sum)
	out := make([]float32, len(vec))
	for i, v := range vec {
		out[i] = float32(v / norm)
	}
	return out
}

// fnv32a is a self-contained FNV-1a 32-bit hash of s.
func fnv32a(s string) uint32 {
	const (
		offset32 uint32 = 2166136261
		prime32  uint32 = 16777619
	)
	h := offset32
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}
