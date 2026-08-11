package sureauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// testServer returns a client wired to an httptest server that routes by path.
func testServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewWithConfig(Config{ServerURL: srv.URL, APIKey: "test-key"})
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func TestNewRequiresAPIKey(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvServerURL, "")
	if _, err := New(); err == nil {
		t.Fatal("expected error without API key")
	}
	t.Setenv(EnvAPIKey, "key")
	if _, err := New(); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestRegisterAndLogin(t *testing.T) {
	c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" {
			writeJSON(w, 401, map[string]interface{}{"success": false, "error": map[string]string{"code": "UNAUTHORIZED", "message": "bad key"}})
			return
		}
		switch r.URL.Path {
		case "/api/v1/auth/register":
			writeJSON(w, 200, map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"access_token": "reg-token", "refresh_token": "reg-refresh",
					"expires_in": 900, "token_type": "Bearer",
					"user": map[string]interface{}{"email": "a@b.c"},
				},
			})
		case "/api/v1/auth/login":
			writeJSON(w, 200, map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"access_token": "login-token", "refresh_token": "login-refresh",
					"expires_in": 900,
				},
			})
		default:
			writeJSON(w, 404, map[string]interface{}{"success": false, "error": map[string]string{"code": "NOT_FOUND", "message": r.URL.Path}})
		}
	})

	ctx := context.Background()
	reg, err := c.Register(ctx, AuthRequest{Email: "a@b.c", Password: "Secret123!"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.AccessToken != "reg-token" || reg.User == nil || reg.User.Email != "a@b.c" {
		t.Fatalf("register = %+v", reg)
	}
	auth, err := c.Auth(ctx, "a@b.c", "Secret123!")
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if auth.AccessToken != "login-token" {
		t.Fatalf("login = %+v", auth)
	}
}

func TestOTPChallengeFlow(t *testing.T) {
	c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login":
			writeJSON(w, 200, map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"challenges": []map[string]string{{"type": "otp_required", "field": "user@x.com"}},
				},
			})
		case "/api/v1/auth/otp/send":
			writeJSON(w, 200, map[string]interface{}{"success": true, "data": map[string]interface{}{
				"message_id": "m1", "channel": "email", "expires_in": 300, "cost": 0, "currency": "USD",
			}})
		case "/api/v1/auth/otp/verify":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["code"] != "123456" {
				writeJSON(w, 400, map[string]interface{}{"success": false, "error": map[string]string{"code": "VALIDATION_ERROR", "message": "invalid OTP code"}})
				return
			}
			writeJSON(w, 200, map[string]interface{}{"success": true, "data": map[string]interface{}{"access_token": "otp-token"}})
		default:
			writeJSON(w, 404, map[string]interface{}{"success": false, "error": map[string]string{"code": "NOT_FOUND", "message": r.URL.Path}})
		}
	})

	ctx := context.Background()
	res, err := c.Login(ctx, "user@x.com", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(res.Challenges) != 1 || res.Challenges[0].Type != ChallengeOTPRequired {
		t.Fatalf("expected otp challenge, got %+v", res.Challenges)
	}
	if _, err := c.SendOTP(ctx, SendOTPRequest{Identifier: "user@x.com", Purpose: "login"}); err != nil {
		t.Fatalf("SendOTP: %v", err)
	}
	done, err := c.VerifyOTP(ctx, "user@x.com", "123456")
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}
	if done.AccessToken != "otp-token" {
		t.Fatalf("verify = %+v", done)
	}
	if _, err := c.VerifyOTP(ctx, "user@x.com", "000000"); err == nil {
		t.Fatal("expected error on wrong code")
	}
}

func TestSettingsAndLoginURL(t *testing.T) {
	c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/settings" {
			writeJSON(w, 200, map[string]interface{}{"success": true, "data": map[string]interface{}{
				"ProjectID": "proj-1", "IdentifierType": "phone", "CredentialType": "pin",
				"PinLength": 6, "AllowRegistration": true, "AllowGoogleSSO": true,
			}})
			return
		}
		writeJSON(w, 404, map[string]interface{}{"success": false, "error": map[string]string{"code": "NOT_FOUND", "message": r.URL.Path}})
	})
	ctx := context.Background()
	s, err := c.Settings(ctx)
	if err != nil || s.ProjectID != "proj-1" || s.CredentialType != "pin" {
		t.Fatalf("settings = %+v, %v", s, err)
	}
	u, err := c.LoginURL(ctx, "https://app.com/cb")
	if err != nil {
		t.Fatalf("LoginURL: %v", err)
	}
	if !strings.Contains(u, "/oauth/authorize?") || !strings.Contains(u, "client_id=proj-1") || !strings.Contains(u, "redirect_uri=") {
		t.Fatalf("login url = %s", u)
	}
}

func TestCompleteLoginExchangesCode(t *testing.T) {
	c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects/settings":
			writeJSON(w, 200, map[string]interface{}{"success": true, "data": map[string]interface{}{"ProjectID": "proj-1"}})
		case "/oauth/token":
			if r.Header.Get("X-API-Key") != "test-key" {
				writeJSON(w, 401, map[string]interface{}{"success": false})
				return
			}
			r.ParseForm()
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code-abc" {
				writeJSON(w, 400, map[string]interface{}{"error": "invalid_grant", "error_description": "bad code"})
				return
			}
			writeJSON(w, 200, map[string]interface{}{"access_token": "exchanged", "refresh_token": "r", "expires_in": 900, "token_type": "Bearer"})
		default:
			writeJSON(w, 404, map[string]interface{}{"success": false})
		}
	})
	ctx := context.Background()
	res, err := c.CompleteLogin(ctx, "code-abc", "https://app.com/cb")
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if res.AccessToken != "exchanged" {
		t.Fatalf("result = %+v", res)
	}
}

func TestAPIErrorTyped(t *testing.T) {
	c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 400, map[string]interface{}{"success": false, "error": map[string]string{"code": "VALIDATION_ERROR", "message": "invalid PIN"}})
	})
	_, err := c.Login(context.Background(), "x", "y")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "VALIDATION_ERROR" || apiErr.Message != "invalid PIN" {
		t.Fatalf("apiErr = %+v", apiErr)
	}
}

func TestEnvDrivenClient(t *testing.T) {
	t.Setenv(EnvAPIKey, "env-key")
	t.Setenv(EnvServerURL, "http://env.example.com")
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.APIKey != "env-key" || c.ServerURL != "http://env.example.com" {
		t.Fatalf("client = %+v", c)
	}
}

var _ = os.Getenv
