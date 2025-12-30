package gosureauth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// These tests require a running SureAuth server
// Run with: DB_NAME=irongate go run ../../cmd/server/main.go
// Then: go test -v

func getTestClient() *Client {
	baseURL := os.Getenv("TEST_SERVER_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	apiKey := os.Getenv("TEST_API_KEY")
	if apiKey == "" {
		apiKey = "test-api-key" // Use a real API key from your test project
	}

	apiSecret := os.Getenv("TEST_API_SECRET")
	if apiSecret == "" {
		apiSecret = "test-api-secret" // Use a real API secret from your test project
	}

	return NewWithDefaults(baseURL, apiKey, apiSecret)
}

func TestClientCreation(t *testing.T) {
	client := getTestClient()
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.baseURL == "" {
		t.Error("Expected baseURL to be set")
	}
}

func TestRegister(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := getTestClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate unique email/username for test using nanoseconds
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "test-" + unique + "@example.com"
	username := "testuser" + unique

	result, err := client.Register(ctx, RegisterRequest{
		Email:    email,
		Password: "TestPassword123!",
		Username: username,
	})

	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if result.User.Email != email {
		t.Errorf("Expected email %s, got %s", email, result.User.Email)
	}

	if result.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}

	if result.RefreshToken == "" {
		t.Error("Expected non-empty refresh token")
	}

	t.Logf("Registered user: %s (ID: %s)", result.User.Email, result.User.ID)
}

func TestLoginAndValidate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := getTestClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First register a user
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "logintest-" + unique + "@example.com"
	username := "logintest" + unique
	password := "TestPassword123!"

	_, err := client.Register(ctx, RegisterRequest{
		Email:    email,
		Password: password,
		Username: username,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Now login
	loginResult, err := client.Login(ctx, email, password)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if loginResult.AccessToken == "" {
		t.Error("Expected non-empty access token from login")
	}

	t.Logf("Login successful, token type: %s, expires in: %ds", loginResult.TokenType, loginResult.ExpiresIn)

	// Validate the token
	validation, err := client.ValidateToken(ctx, loginResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if !validation.Valid {
		t.Error("Expected token to be valid")
	}

	if validation.Email != email {
		t.Errorf("Expected email %s, got %s", email, validation.Email)
	}

	t.Logf("Token valid for user: %s (ID: %s)", validation.Email, validation.UserID)
}

func TestRefreshToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := getTestClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Register and login
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "refreshtest-" + unique + "@example.com"
	username := "refreshtest" + unique
	password := "TestPassword123!"

	_, err := client.Register(ctx, RegisterRequest{
		Email:    email,
		Password: password,
		Username: username,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	loginResult, err := client.Login(ctx, email, password)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Refresh the token
	newToken, err := client.RefreshToken(ctx, loginResult.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	if newToken == "" {
		t.Error("Expected non-empty new access token")
	}

	// The new token should be valid
	validation, err := client.ValidateToken(ctx, newToken)
	if err != nil {
		t.Fatalf("ValidateToken for new token failed: %v", err)
	}

	if !validation.Valid {
		t.Error("Expected refreshed token to be valid")
	}

	t.Logf("Refreshed token is valid for user: %s", validation.Email)
}

func TestLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := getTestClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Register and login
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "logouttest-" + unique + "@example.com"
	username := "logouttest" + unique
	password := "TestPassword123!"

	_, err := client.Register(ctx, RegisterRequest{
		Email:    email,
		Password: password,
		Username: username,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	loginResult, err := client.Login(ctx, email, password)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Logout
	err = client.Logout(ctx, loginResult.AccessToken)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	t.Log("Logout successful")
}

func TestTokenManager(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := getTestClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Register and login
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "tokenmanager-" + unique + "@example.com"
	username := "tokenmanager" + unique
	password := "TestPassword123!"

	_, err := client.Register(ctx, RegisterRequest{
		Email:    email,
		Password: password,
		Username: username,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	loginResult, err := client.Login(ctx, email, password)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Create token manager
	tm := NewTokenManager(client, loginResult.AccessToken, loginResult.RefreshToken, loginResult.ExpiresIn)

	// Set refresh callback
	refreshed := false
	tm.OnRefresh(func(newToken string) {
		refreshed = true
		t.Logf("Token refreshed: %s...", newToken[:20])
	})

	// Get access token (should return current token since not expired)
	token, err := tm.GetAccessToken(ctx)
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token from TokenManager")
	}

	if tm.IsExpired() {
		t.Error("Token should not be expired immediately after login")
	}

	// Note: refreshed would be true if we forced a refresh by setting a short expiry
	_ = refreshed // Suppress unused variable warning - would be used in extended tests

	t.Log("TokenManager working correctly")
}

func TestAPIErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := getTestClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to login with invalid credentials
	_, err := client.Login(ctx, "nonexistent@example.com", "wrongpassword")
	if err == nil {
		t.Fatal("Expected login to fail with invalid credentials")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("Expected APIError, got %T: %v", err, err)
	}

	if !apiErr.IsUnauthorized() {
		t.Logf("Got error: %s (%s)", apiErr.Message, apiErr.Code)
	}

	t.Logf("Correctly received API error: %s", apiErr.Error())
}
