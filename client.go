// Package gosureauth provides a Go client library for SureAuth SaaS authentication
package gosureauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the main SureAuth client
type Client struct {
	baseURL    string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

// Config holds client configuration options
type Config struct {
	BaseURL   string
	APIKey    string
	APISecret string
	Timeout   time.Duration
}

// New creates a new SureAuth client
func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	return &Client{
		baseURL:   cfg.BaseURL,
		apiKey:    cfg.APIKey,
		apiSecret: cfg.APISecret,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// NewWithDefaults creates a client with just URL and credentials
func NewWithDefaults(baseURL, apiKey, apiSecret string) *Client {
	return New(Config{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		APISecret: apiSecret,
		Timeout:   30 * time.Second,
	})
}

// Response represents the standard API response
type Response struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *ErrorInfo      `json:"error,omitempty"`
	Meta    *MetaInfo       `json:"meta,omitempty"`
}

// ErrorInfo represents error details
type ErrorInfo struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

// MetaInfo represents request metadata
type MetaInfo struct {
	RequestID string `json:"request_id"`
	Timestamp int64  `json:"timestamp"`
}

// User represents a user account
type User struct {
	ID         string                 `json:"id"`
	Email      string                 `json:"email"`
	Username   string                 `json:"username,omitempty"`
	Phone      string                 `json:"phone,omitempty"`
	IsActive   bool                   `json:"is_active"`
	IsVerified bool                   `json:"is_verified"`
	CreatedAt  string                 `json:"created_at"`
	Custom     map[string]interface{} `json:"custom,omitempty"`
}

// AuthResult represents authentication result
type AuthResult struct {
	User         User     `json:"user"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	TokenType    string   `json:"token_type"`
	RequiresMFA  bool     `json:"requires_mfa"`
	MFAMethods   []string `json:"mfa_methods,omitempty"`
}

// TokenValidation represents token validation result
type TokenValidation struct {
	Valid        bool                   `json:"valid"`
	UserID       string                 `json:"user_id,omitempty"`
	Email        string                 `json:"email,omitempty"`
	Username     string                 `json:"username,omitempty"`
	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

// RegisterRequest represents registration parameters
type RegisterRequest struct {
	Email    string                 `json:"email"`
	Username string                 `json:"username,omitempty"`
	Password string                 `json:"password"`
	Phone    string                 `json:"phone,omitempty"`
	Custom   map[string]interface{} `json:"custom,omitempty"`
}

// LoginRequest represents login parameters
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Register creates a new user account
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*AuthResult, error) {
	var result AuthResult
	if err := c.post(ctx, "/api/v1/auth/register", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Login authenticates a user
func (c *Client) Login(ctx context.Context, email, password string) (*AuthResult, error) {
	req := LoginRequest{Email: email, Password: password}
	var result AuthResult
	if err := c.post(ctx, "/api/v1/auth/login", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Logout invalidates the current session
func (c *Client) Logout(ctx context.Context, accessToken string) error {
	req := struct{}{}
	return c.postWithAuth(ctx, "/api/v1/auth/logout", req, nil, accessToken)
}

// RefreshToken exchanges a refresh token for a new access token
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	req := map[string]string{"refresh_token": refreshToken}
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := c.post(ctx, "/api/v1/auth/refresh", req, &result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

// ValidateToken validates an access token and returns claims
func (c *Client) ValidateToken(ctx context.Context, token string) (*TokenValidation, error) {
	req := map[string]string{"token": token}
	var result TokenValidation
	if err := c.post(ctx, "/api/v1/auth/validate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// HTTP helper methods

func (c *Client) post(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.doRequest(ctx, "POST", path, body, result, "")
}

func (c *Client) postWithAuth(ctx context.Context, path string, body interface{}, result interface{}, bearerToken string) error {
	return c.doRequest(ctx, "POST", path, body, result, bearerToken)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}, bearerToken string) error {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("X-API-Secret", c.apiSecret)

	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var apiResp Response
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for errors
	if !apiResp.Success {
		if apiResp.Error != nil {
			return &APIError{
				Code:      apiResp.Error.Code,
				Message:   apiResp.Error.Message,
				Details:   apiResp.Error.Details,
				RequestID: apiResp.Meta.RequestID,
			}
		}
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	// Unmarshal data into result
	if result != nil && apiResp.Data != nil {
		if err := json.Unmarshal(apiResp.Data, result); err != nil {
			return fmt.Errorf("failed to parse result: %w", err)
		}
	}

	return nil
}

// APIError represents an API error
type APIError struct {
	Code      string
	Message   string
	Details   map[string]string
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s (request_id: %s)", e.Code, e.Message, e.RequestID)
}

// IsUnauthorized returns true if the error is an authentication error
func (e *APIError) IsUnauthorized() bool {
	return e.Code == "UNAUTHORIZED" || e.Code == "INVALID_API_KEY"
}

// IsTokenExpired returns true if the error is due to token expiration
func (e *APIError) IsTokenExpired() bool {
	return e.Code == "TOKEN_EXPIRED"
}

// IsValidationError returns true if the error is a validation error
func (e *APIError) IsValidationError() bool {
	return e.Code == "VALIDATION_ERROR"
}
