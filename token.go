package gosureauth

import (
	"context"
	"sync"
	"time"
)

// TokenManager handles automatic token refresh
type TokenManager struct {
	client       *Client
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	mu           sync.RWMutex
	onRefresh    func(newToken string)
}

// NewTokenManager creates a token manager
func NewTokenManager(client *Client, accessToken, refreshToken string, expiresIn int64) *TokenManager {
	return &TokenManager{
		client:       client,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
}

// OnRefresh sets a callback for when tokens are refreshed
func (tm *TokenManager) OnRefresh(callback func(newToken string)) {
	tm.onRefresh = callback
}

// GetAccessToken returns a valid access token, refreshing if needed
func (tm *TokenManager) GetAccessToken(ctx context.Context) (string, error) {
	tm.mu.RLock()
	token := tm.accessToken
	expires := tm.expiresAt
	tm.mu.RUnlock()

	// If token is still valid with some buffer (30 seconds)
	if time.Now().Add(30 * time.Second).Before(expires) {
		return token, nil
	}

	// Need to refresh
	return tm.refresh(ctx)
}

// refresh performs token refresh
func (tm *TokenManager) refresh(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring lock
	if time.Now().Add(30 * time.Second).Before(tm.expiresAt) {
		return tm.accessToken, nil
	}

	newToken, err := tm.client.RefreshToken(ctx, tm.refreshToken)
	if err != nil {
		return "", err
	}

	tm.accessToken = newToken
	tm.expiresAt = time.Now().Add(15 * time.Minute) // Assume 15 min expiry

	if tm.onRefresh != nil {
		tm.onRefresh(newToken)
	}

	return newToken, nil
}

// SetTokens updates the stored tokens
func (tm *TokenManager) SetTokens(accessToken, refreshToken string, expiresIn int64) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tm.accessToken = accessToken
	tm.refreshToken = refreshToken
	tm.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
}

// IsExpired returns true if the access token is expired
func (tm *TokenManager) IsExpired() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return time.Now().After(tm.expiresAt)
}

// GetRefreshToken returns the current refresh token
func (tm *TokenManager) GetRefreshToken() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.refreshToken
}
