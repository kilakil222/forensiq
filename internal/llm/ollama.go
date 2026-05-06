// Package llm provides a lightweight Ollama client for forensic analysis queries.
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultBase = "http://localhost:11434"

// SystemPrompt returns the DFIR analyst system prompt for LLM queries.
func SystemPrompt() string { return systemPrompt }

// Client is a minimal Ollama API client.
type Client struct {
	Base  string
	Model string
	http  *http.Client
}

// New creates a Client. base defaults to http://localhost:11434.
func New(base, model string) *Client {
	if base == "" {
		base = defaultBase
	}
	if model == "" {
		model = "qwen2.5:7b"
	}
	return &Client{Base: base, Model: model, http: &http.Client{Timeout: 120 * time.Second}}
}

type generateReq struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system"`
	Stream bool   `json:"stream"`
}

type generateResp struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

// Ask sends a prompt with the given system context and returns the response text.
func (c *Client) Ask(system, prompt string) (string, error) {
	body, _ := json.Marshal(generateReq{
		Model:  c.Model,
		System: system,
		Prompt: prompt,
		Stream: false,
	})

	resp, err := c.http.Post(c.Base+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("ollama: %w (is Ollama running? ollama serve)", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ollama: read response: %w", err)
	}

	var r generateResp
	if err := json.Unmarshal(data, &r); err != nil {
		return "", fmt.Errorf("ollama: parse response: %w", err)
	}
	if r.Error != "" {
		return "", fmt.Errorf("ollama: %s", r.Error)
	}
	return strings.TrimSpace(r.Response), nil
}

// Models lists available models from Ollama.
func (c *Client) Models() ([]string, error) {
	resp, err := c.http.Get(c.Base + "/api/tags")
	if err != nil {
		return nil, fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	var names []string
	for _, m := range result.Models {
		names = append(names, m.Name)
	}
	return names, nil
}
