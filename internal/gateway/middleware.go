package gateway

import (
	"log"
	"net/http"
	"strings"
)

// keyExtractor pulls the client API key out of a request. It returns the key,
// or a client-facing message describing why no key could be found.
type keyExtractor func(r *http.Request) (apiKey string, errMsg string)

// headerKey extracts the API key from the Authorization header (S3 mode).
func headerKey(r *http.Request) (string, string) {
	return bearerToken(r, "Missing or invalid Authorization header")
}

// pathOrHeaderKey extracts the API key from a single-segment URL path
// (format: /<token>), falling back to the Authorization header (RPC mode).
// When the token comes from the path, the path is rewritten to / so the
// backend never sees the key.
func pathOrHeaderKey(r *http.Request) (string, string) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path != "" && !strings.Contains(path, "/") {
		r.URL.Path = "/"
		r.URL.RawPath = ""
		return path, ""
	}
	return bearerToken(r, "Missing or invalid Authorization header or token in URL path")
}

func bearerToken(r *http.Request, missingMsg string) (string, string) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", missingMsg
	}
	apiKey := strings.TrimPrefix(auth, "Bearer ")
	if apiKey == "" {
		return "", "Empty API key"
	}
	return apiKey, ""
}

// requireAPIKey wraps next with API key authentication.
func (g *Gateway) requireAPIKey(extract keyExtractor, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for CORS preflight requests
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		apiKey, errMsg := extract(r)
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusUnauthorized)
			return
		}

		isAuthenticated, err := g.authenticator.ValidateAPIKey(r.Context(), apiKey)
		if err != nil {
			log.Printf("Authentication error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !isAuthenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
