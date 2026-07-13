package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type RPCHealthChecker struct {
	rpcURL     string
	httpClient *http.Client
}

type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      int                    `json:"id"`
	Result  map[string]interface{} `json:"result"`
	Error   *JSONRPCError          `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func NewRPCHealthChecker(rpcURL string) *RPCHealthChecker {
	return &RPCHealthChecker{
		rpcURL: rpcURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CheckHealth calls the backend's getHealth method and returns nil when the
// backend reports itself healthy.
func (h *RPCHealthChecker) CheckHealth(ctx context.Context) error {
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      0,
		Method:  "getHealth",
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON-RPC request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", h.rpcURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("RPC server unreachable: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RPC server returned status: %d", resp.StatusCode)
	}

	var rpcResponse JSONRPCResponse
	if err := json.Unmarshal(body, &rpcResponse); err != nil {
		return fmt.Errorf("failed to unmarshal JSON-RPC response: %v", err)
	}

	if rpcResponse.Error != nil {
		return fmt.Errorf("RPC error: %s", rpcResponse.Error.Message)
	}

	if status, ok := rpcResponse.Result["status"].(string); !ok || status != "healthy" {
		return fmt.Errorf("service is not healthy")
	}

	return nil
}
