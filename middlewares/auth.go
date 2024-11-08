package middlewares

import (
	"errors"
	"strings"
	"time"

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
	TwoFAVerified bool   `json:"twoFA_verified"`
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
func (config *JWTConfig) GenerateTokens(userID string, otpFaVerified bool, authMethod, device, url string) (accessToken, refreshToken string, err error) {
	// Generate access token
	accessToken, err = config.generateToken(userID, otpFaVerified, authMethod, "access", device, url, config.AccessTokenDuration)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshToken, err = config.generateToken(userID, otpFaVerified, authMethod, "refresh", device, url, config.RefreshTokenDuration)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// generateToken creates a single token
func (config *JWTConfig) generateToken(userID string, otpFaVerified bool, authMethod, tokenType, device, url string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		ID:            userID,
		AMR:           authMethod,
		Type:          tokenType,
		Device:        device,
		URL:           url,
		TwoFAVerified: otpFaVerified,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.SecretKey))
}

// IsAuthenticated middleware checks for valid access token and handles automatic refresh
func IsAuthenticated(config *JWTConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var tokenString string
		var tokenMissing bool

		// Capture URL and determine device type
		url := c.OriginalURL()
		userAgent := c.Get("User-Agent")
		device := "desktop"
		if strings.Contains(strings.ToLower(userAgent), "mobile") {
			device = "mobile"
		}

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
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "unauthorized",
				})
			}

			newAccessToken, err := handleTokenRefresh(refreshToken, config, device, url)
			if err != nil {
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

				newAccessToken, err := handleTokenRefresh(refreshToken, config, device, url)
				if err != nil {
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

		// Check if device and URL match the token
		if claims.Device != device || claims.URL != url {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "mismatched device or URL",
			})
		}

		// Store user info in context
		c.Locals("user_id", claims.ID)
		return c.Next()
	}
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

				if !claims.TwoFAVerified {
					return c.Redirect("/login/setup2fa")
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
					if !claims.TwoFAVerified {
						return c.Redirect("/login/setup2fa")
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
	return config.generateToken(claims.ID, claims.TwoFAVerified, claims.AMR, "access", device, url, config.AccessTokenDuration)
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
