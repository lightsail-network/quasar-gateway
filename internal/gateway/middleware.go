package gateway

import (
	"log/slog"
	"net/http"
	"strings"
)

// corsMiddleware terminates CORS preflight requests and stamps
// Access-Control-Allow-Origin on every response. The gateway allows any
// origin by design: access control is per API key, not per origin.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Preflight requests terminate here: they never carry credentials,
		// so they skip authentication and must never reach the backend.
		if r.Method == http.MethodOptions {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			// Per the Fetch spec a wildcard does not cover Authorization,
			// so it must be listed explicitly.
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
			h.Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(&corsResponseWriter{ResponseWriter: w}, r)
	})
}

// corsResponseWriter sets Access-Control-Allow-Origin right before the
// response header is written. This keeps error responses (401, 502, ...)
// readable from browser scripts, and setting instead of adding means an
// Allow-Origin header copied from the backend by the reverse proxy cannot
// end up duplicated (browsers reject "*, *").
type corsResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *corsResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *corsResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer, keeping
// Flush and Hijack working for the reverse proxy.
func (w *corsResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

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

// requireAPIKey wraps next with API key authentication. CORS preflight
// requests never get here: corsMiddleware terminates them.
func (g *Gateway) requireAPIKey(extract keyExtractor, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey, errMsg := extract(r)
		if errMsg != "" {
			http.Error(w, errMsg, http.StatusUnauthorized)
			return
		}

		isAuthenticated, err := g.authenticator.ValidateAPIKey(r.Context(), apiKey)
		if err != nil {
			slog.Error("authentication error", "error", err)
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
