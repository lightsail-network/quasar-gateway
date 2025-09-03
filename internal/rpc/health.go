package rpc

import (
	"bytes"
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

func createUnhealthyResponse(reason string) []byte {
	response := fmt.Sprintf(`{"status":"unhealthy","reason":"%s"}`, reason)
	return []byte(response)
}

func (h *RPCHealthChecker) CheckHealth() (int, []byte, error) {
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      0,
		Method:  "getHealth",
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return http.StatusServiceUnavailable, createUnhealthyResponse("failed to marshal request"), fmt.Errorf("failed to marshal JSON-RPC request: %v", err)
	}

	req, err := http.NewRequest("POST", h.rpcURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return http.StatusServiceUnavailable, createUnhealthyResponse("failed to create request"), fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return http.StatusServiceUnavailable, createUnhealthyResponse("RPC server unreachable"), fmt.Errorf("failed to make request to RPC server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return http.StatusServiceUnavailable, createUnhealthyResponse("failed to read response"), fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return http.StatusServiceUnavailable, createUnhealthyResponse("RPC server error"), fmt.Errorf("RPC server returned status: %d", resp.StatusCode)
	}

	var rpcResponse JSONRPCResponse
	if err := json.Unmarshal(body, &rpcResponse); err != nil {
		return http.StatusServiceUnavailable, createUnhealthyResponse("invalid RPC response"), fmt.Errorf("failed to unmarshal JSON-RPC response: %v", err)
	}

	if rpcResponse.Error != nil {
		return http.StatusServiceUnavailable, createUnhealthyResponse("RPC error"), fmt.Errorf("RPC error: %s", rpcResponse.Error.Message)
	}

	if status, ok := rpcResponse.Result["status"].(string); ok && status == "healthy" {
		// Return simple status response instead of full RPC response
		simpleResponse := map[string]string{"status": "healthy"}
		simpleBody, err := json.Marshal(simpleResponse)
		if err != nil {
			return http.StatusServiceUnavailable, createUnhealthyResponse("failed to marshal response"), fmt.Errorf("failed to marshal simple response: %v", err)
		}
		return http.StatusOK, simpleBody, nil
	}

	return http.StatusServiceUnavailable, createUnhealthyResponse("service not healthy"), fmt.Errorf("service is not healthy")
}
