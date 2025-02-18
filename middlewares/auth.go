package middlewares

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Zenk41/simple-file-web/views/error_handling"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidSignature = errors.New("invalid signing method")
)

type JWTConfig struct {
	SecretKey            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

type JWTClaims struct {
	ID            string `json:"id"`
	AMR           string `json:"amr"`
	Type          string `json:"type"`   // "access" or "refresh"
	Device        string `json:"device"` // "mobile" or "desktop"
	URL           string `json:"url"`    // URL associated with token issuance
	TwoFAEnabled  bool   `json:"twoFA_enabled"`
	TwoFAVerified bool   `json:"twoFA_verified"`
	IsAdmin       bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

// NewJWTConfig creates a new JWT configuration
func NewJWTConfig(secretKey string) *JWTConfig {
	return &JWTConfig{
		SecretKey:            secretKey,
		AccessTokenDuration:  15 * time.Minute, // Short-lived access token
		RefreshTokenDuration: 24 * time.Hour,   // Longer-lived refresh token
	}
}

// GenerateTokens creates both access and refresh tokens
func (config *JWTConfig) GenerateTokens(userID string, isAdmin bool, otpFaVerified, otpFaEnabled bool, authMethod, device, url string) (accessToken, refreshToken string, err error) {
	// Generate access token
	accessToken, err = config.generateToken(userID, isAdmin, otpFaVerified, otpFaEnabled, authMethod, "access", device, url, config.AccessTokenDuration)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshToken, err = config.generateToken(userID, isAdmin, otpFaVerified, otpFaEnabled, authMethod, "refresh", device, url, config.RefreshTokenDuration)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// generateToken creates a single token
func (config *JWTConfig) generateToken(userID string, isAdmin bool, otpFaVerified, otpFaEnabled bool, authMethod, tokenType, device, url string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		ID:            userID,
		AMR:           authMethod,
		Type:          tokenType,
		Device:        device,
		URL:           url,
		TwoFAVerified: otpFaVerified,
		TwoFAEnabled:  otpFaEnabled,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		IsAdmin: isAdmin,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.SecretKey))
}

func IsAuthenticated(config *JWTConfig, require2FA bool, isPage bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var tokenString string
		var tokenMissing bool

		// Improved device detection - now returns normalized value
		userAgent := c.Get("User-Agent")
		device := detectDevice(userAgent)

		// Get and normalize URL - use proper URL handling
		url := c.BaseURL() // Get base URL first
		fullURL := url

		// Check for token in cookies or authorization header
		if cookie := c.Cookies("access_token"); cookie != "" {
			tokenString = cookie
		} else {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			} else {
				tokenMissing = true
			}
		}

		// Attempt token refresh if missing
		if tokenMissing {
			refreshToken := c.Cookies("refresh_token")
			if refreshToken == "" {
				if isPage {
					c.Set("Content-Type", "text/html")
					return error_handling.Unauthorized().Render(c.Context(), c.Response().BodyWriter())
				}
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "unauthorized",
				})
			}

			newAccessToken, err := handleTokenRefresh(refreshToken, config, device, fullURL)
			if err != nil {
				if isPage {
					c.Set("Content-Type", "text/html")
					return error_handling.InvalidRefreshToken().Render(c.Context(), c.Response().BodyWriter())
				}
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid refresh token",
				})
			}

			cookie := createCookie("access_token", newAccessToken, config.AccessTokenDuration)
			cookie.SameSite = "Strict"
			cookie.Secure = true
			c.Cookie(cookie)

			tokenString = newAccessToken
		}

		// Validate the token and check if it matches device and URL
		claims, err := validateToken(tokenString, config.SecretKey)
		if err != nil {
			if errors.Is(err, ErrTokenExpired) {
				refreshToken := c.Cookies("refresh_token")
				if refreshToken == "" {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "token expired",
					})
				}

				newAccessToken, err := handleTokenRefresh(refreshToken, config, device, fullURL)
				if err != nil {
					if isPage {
						c.Set("Content-Type", "text/html")
						return error_handling.InvalidRefreshToken().Render(c.Context(), c.Response().BodyWriter())
					}
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "invalid refresh token",
					})
				}

				cookie := createCookie("access_token", newAccessToken, config.AccessTokenDuration)
				cookie.SameSite = "Strict"
				cookie.Secure = true
				c.Cookie(cookie)

				claims, err = validateToken(newAccessToken, config.SecretKey)
				if err != nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "token validation failed",
					})
				}
			} else {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid token",
				})
			}
		}

		// Check 2FA if required
		if require2FA && claims.TwoFAEnabled && !claims.TwoFAVerified {
			if isPage {
				return c.Redirect("/login/validateotp?message=need to verify otp if 2fa enabled&type=warning")
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "unauthorized",
				"message": "need to verify otp if 2fa enabled",
			})
		}

		if !isURLMatch(claims.URL, fullURL) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":        "URL mismatch",
				"expected_url": claims.URL,
				"actual_url":   fullURL,
			})
		}

		// Store user info in context
		c.Locals("user_id", claims.ID)
		return c.Next()
	}
}

func IsAuthenticatedAsAdmin(config *JWTConfig, require2FA bool, isPage bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var tokenString string
		var tokenMissing bool

		// Improved device detection - now returns normalized value
		userAgent := c.Get("User-Agent")
		device := detectDevice(userAgent)

		// Get and normalize URL - use proper URL handling
		url := c.BaseURL() // Get base URL first
		fullURL := url

		// Check for token in cookies or authorization header
		if cookie := c.Cookies("access_token"); cookie != "" {
			tokenString = cookie
		} else {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			} else {
				tokenMissing = true
			}
		}

		// Attempt token refresh if missing
		if tokenMissing {
			refreshToken := c.Cookies("refresh_token")
			if refreshToken == "" {
				if isPage {
					c.Set("Content-Type", "text/html")
					return error_handling.Unauthorized().Render(c.Context(), c.Response().BodyWriter())
				}
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "unauthorized",
				})
			}

			newAccessToken, err := handleTokenRefresh(refreshToken, config, device, fullURL)
			if err != nil {
				if isPage {
					c.Set("Content-Type", "text/html")
					return error_handling.InvalidRefreshToken().Render(c.Context(), c.Response().BodyWriter())
				}
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid refresh token",
				})
			}

			cookie := createCookie("access_token", newAccessToken, config.AccessTokenDuration)
			cookie.SameSite = "Strict"
			cookie.Secure = true
			c.Cookie(cookie)

			tokenString = newAccessToken
		}

		// Validate the token and check if it matches device and URL
		claims, err := validateToken(tokenString, config.SecretKey)
		if err != nil {
			if errors.Is(err, ErrTokenExpired) {
				refreshToken := c.Cookies("refresh_token")
				if refreshToken == "" {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "token expired",
					})
				}

				newAccessToken, err := handleTokenRefresh(refreshToken, config, device, fullURL)
				if err != nil {
					if isPage {
						c.Set("Content-Type", "text/html")
						return error_handling.InvalidRefreshToken().Render(c.Context(), c.Response().BodyWriter())
					}
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "invalid refresh token",
					})
				}

				cookie := createCookie("access_token", newAccessToken, config.AccessTokenDuration)
				cookie.SameSite = "Strict"
				cookie.Secure = true
				c.Cookie(cookie)

				claims, err = validateToken(newAccessToken, config.SecretKey)
				if err != nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "token validation failed",
					})
				}
			} else {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid token",
				})
			}
		}

		// Check if user is admin
		if !claims.IsAdmin {
			if isPage {
				c.Set("Content-Type", "text/html")
				return error_handling.Unauthorized().Render(c.Context(), c.Response().BodyWriter())
			}
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "forbidden",
				"message": "admin access required",
			})
		}

		// Check 2FA if required
		if require2FA && claims.TwoFAEnabled && !claims.TwoFAVerified {
			if isPage {
				return c.Redirect("/login/validateotp?message=need to verify otp if 2fa enabled&type=warning")
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "unauthorized",
				"message": "need to verify otp if 2fa enabled",
			})
		}

		if !isURLMatch(claims.URL, fullURL) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":        "URL mismatch",
				"expected_url": claims.URL,
				"actual_url":   fullURL,
			})
		}

		// Store user info in context
		c.Locals("user_id", claims.ID)
		// Store 2fa
		c.Locals("2fa_verified", claims.TwoFAVerified)
		return c.Next()
	}
}

// Helper function to detect device type from User-Agent
func detectDevice(userAgent string) string {
	userAgent = strings.ToLower(userAgent)

	// Updated keywords focusing on current mobile platforms
	mobileKeywords := []string{
		"mobile", "android", "iphone", "ipad",
		"ipod", "webos", "silk", "opera mobi",
		"opera mini", "windows phone", "ucbrowser",
	}

	for _, keyword := range mobileKeywords {
		if strings.Contains(userAgent, keyword) {
			return "mobile"
		}
	}

	return "desktop"
}

// Helper function to normalize URL path
func normalizeURL(url string) string {
	// Remove query parameters if present
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}

	// Remove trailing slash if present
	url = strings.TrimSuffix(url, "/")

	// Ensure path starts with /
	if !strings.HasPrefix(url, "/") {
		url = "/" + url
	}

	return url
}

// Helper function to check if URLs match
func isURLMatch(claimURL, currentURL string) bool {
	// Parse URLs to handle comparison properly
	claim, err1 := url.Parse(claimURL)
	current, err2 := url.Parse(currentURL)

	if err1 != nil || err2 != nil {
		return false
	}

	// Compare host and normalized paths
	return claim.Host == current.Host &&
		normalizeURL(claim.Path) == normalizeURL(current.Path)
}

func RedirectIfAuthenticated(config *JWTConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Capture the device type and original URL for validation
		originalURL := c.OriginalURL()
		userAgent := c.Get("User-Agent")
		deviceType := "desktop"
		if strings.Contains(strings.ToLower(userAgent), "mobi") {
			deviceType = "mobile"
		}

		// Check access token first
		accessToken := c.Cookies("access_token")
		if accessToken != "" {
			claims, err := validateToken(accessToken, config.SecretKey)
			if err == nil && claims.Type == "access" {

				if !claims.TwoFAVerified && claims.TwoFAEnabled {
					return c.Redirect("/login/validateotp")
				}
				// Valid access token - redirect to home
				return c.Redirect("/")
			}
		}

		// If access token is invalid/expired, check refresh token
		refreshToken := c.Cookies("refresh_token")
		if refreshToken != "" {
			// Pass deviceType and originalURL to handleTokenRefresh
			newAccessToken, err := handleTokenRefresh(refreshToken, config, deviceType, originalURL)
			if err == nil {
				// Set new access token cookie
				c.Cookie(createCookie("access_token", newAccessToken, config.AccessTokenDuration))
				claims, err := validateToken(newAccessToken, config.SecretKey)
				if err == nil && claims.Type == "access" {
					if !claims.TwoFAVerified && claims.TwoFAEnabled {
						return c.Redirect("/login/validateotp")
					}
					return c.Redirect("/")
				}
			}
		}

		// No valid tokens found - allow access to auth routes
		return c.Next()
	}
}

// handleTokenRefresh validates refresh token and generates new access token
func handleTokenRefresh(refreshToken string, config *JWTConfig, device, url string) (string, error) {
	claims, err := validateToken(refreshToken, config.SecretKey)
	if err != nil || claims.Type != "refresh" || claims.Device != device || claims.URL != url {
		return "", ErrInvalidToken
	}

	// Generate a new access token with the original device and URL info
	return config.generateToken(claims.ID, claims.IsAdmin, claims.TwoFAVerified, claims.TwoFAEnabled, claims.AMR, "access", device, url, config.AccessTokenDuration)
}

// validateToken verifies and parses a JWT token
func validateToken(tokenString, secretKey string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSignature
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// DecodeToken decodes the JWT token and returns the claims
func (config *JWTConfig) DecodeToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSignature
		}
		return []byte(config.SecretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// createCookie creates a new cookie with the specified parameters
func createCookie(name, value string, expiry time.Duration) *fiber.Cookie {
	return &fiber.Cookie{
		Name:     name,
		Value:    value,
		Expires:  time.Now().Add(expiry),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
	}
}

// SetAuthCookies sets both access and refresh token cookies
func SetAuthCookies(c *fiber.Ctx, accessToken, refreshToken string, config *JWTConfig) {
	c.Cookie(createCookie("access_token", accessToken, config.AccessTokenDuration))
	c.Cookie(createCookie("refresh_token", refreshToken, config.RefreshTokenDuration))
}

// ClearAuthCookies removes both access and refresh token cookies
func ClearAuthCookies(c *fiber.Ctx) {
	c.Cookie(createCookie("access_token", "", -1*time.Hour))
	c.Cookie(createCookie("refresh_token", "", -1*time.Hour))
}
