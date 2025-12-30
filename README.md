# gosimpleauth

Go client library for MedaAuth SaaS authentication service.

## Installation

```bash
go get github.com/medatechnology/gosimpleauth@latest
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/medatechnology/medaauth/clients/gosimpleauth"
)

func main() {
    // Create client with API credentials
    client := gosimpleauth.NewWithDefaults(
        "https://auth.example.com",
        "your_api_key",
        "your_api_secret",
    )

    ctx := context.Background()

    // Register a new user
    auth, err := client.Register(ctx, gosimpleauth.RegisterRequest{
        Email:    "user@example.com",
        Password: "secure_password",
        Username: "username",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Registered user: %s\n", auth.User.Email)

    // Login
    auth, err = client.Login(ctx, "user@example.com", "secure_password")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Access Token: %s\n", auth.AccessToken)

    // Validate token
    validation, err := client.ValidateToken(ctx, auth.AccessToken)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Token valid: %v, User: %s\n", validation.Valid, validation.Email)

    // Logout
    if err := client.Logout(ctx, auth.AccessToken); err != nil {
        log.Fatal(err)
    }
    fmt.Println("Logged out successfully")
}
```

## Token Management

For automatic token refresh:

```go
// After successful login
tokenMgr := gosimpleauth.NewTokenManager(
    client,
    auth.AccessToken,
    auth.RefreshToken,
    auth.ExpiresIn,
)

// Set callback for token refresh (e.g., to update stored tokens)
tokenMgr.OnRefresh(func(newToken string) {
    fmt.Println("Token refreshed:", newToken)
})

// Get a valid access token (auto-refreshes if needed)
token, err := tokenMgr.GetAccessToken(ctx)
if err != nil {
    log.Fatal(err)
}
```

## Error Handling

```go
auth, err := client.Login(ctx, email, password)
if err != nil {
    if apiErr, ok := err.(*gosimpleauth.APIError); ok {
        if apiErr.IsUnauthorized() {
            fmt.Println("Invalid credentials")
        } else if apiErr.IsTokenExpired() {
            fmt.Println("Token expired, please refresh")
        }
        fmt.Printf("Error: %s (code: %s)\n", apiErr.Message, apiErr.Code)
    }
    return
}
```

## Renaming This Library

If you need to rename this library in the future:

1. **Rename the directory** to your new name
2. **Update `go.mod`**: Change `module github.com/medatechnology/gosimpleauth` to your new module path
3. **Update package declaration** in all `.go` files (first line of each file)
4. **Create new GitHub repo** with the new name and push

The Go module path in `go.mod` is what users will `go get`, so choose something memorable!
