package rpc

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type RPCProxy struct {
	proxy *httputil.ReverseProxy
}

func NewRPCProxy(target string) (*RPCProxy, error) {
	if target == "" {
		return nil, fmt.Errorf("target URL cannot be empty")
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %v", err)
	}

	if targetURL.Scheme == "" || targetURL.Host == "" {
		return nil, fmt.Errorf("invalid target URL: missing scheme or host")
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, fmt.Sprintf("Proxy error: %v", err), http.StatusBadGateway)
	}

	return &RPCProxy{
		proxy: proxy,
	}, nil
}

func (rp *RPCProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp.proxy.ServeHTTP(w, r)
}

func (rp *RPCProxy) ServeHTTPWithAuth(w http.ResponseWriter, r *http.Request, isAuthenticated bool) {
	if !isAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rp.proxy.ServeHTTP(w, r)
}
