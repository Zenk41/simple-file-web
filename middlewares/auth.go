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
	ID   string `json:"id"`
	AMR  string `json:"amr"`
	Type string `json:"type"` // "access" or "refresh"
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
func (config *JWTConfig) GenerateTokens(userID, authMethod string) (accessToken, refreshToken string, err error) {
	// Generate access token
	accessToken, err = config.generateToken(userID, authMethod, "access", config.AccessTokenDuration)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshToken, err = config.generateToken(userID, authMethod, "refresh", config.RefreshTokenDuration)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// generateToken creates a single token
func (config *JWTConfig) generateToken(userID, authMethod, tokenType string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		ID:   userID,
		AMR:  authMethod,
		Type: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.SecretKey))
}

// IsAuthenticated middleware checks for valid access token
func IsAuthenticated(config *JWTConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var tokenString string

		// Check cookie first
		if cookie := c.Cookies("access_token"); cookie != "" {
			tokenString = cookie
		} else {
			// Check Authorization header
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unauthorized",
			})
		}

		claims, err := validateToken(tokenString, config.SecretKey)
		if err != nil {
			if errors.Is(err, ErrTokenExpired) {
				// Try to refresh the token
				refreshToken := c.Cookies("refresh_token")
				if refreshToken == "" {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "token expired",
					})
				}

				newAccessToken, err := handleTokenRefresh(refreshToken, config)
				if err != nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "invalid refresh token",
					})
				}

				// Set new access token cookie
				c.Cookie(createCookie("access_token", newAccessToken, config.AccessTokenDuration))

				// Update token string for further processing
				tokenString = newAccessToken
				claims, err = validateToken(tokenString, config.SecretKey)
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

		// Store user info in context
		c.Locals("user_id", claims.ID)
		return c.Next()
	}
}

func RedirectIfAuthenticated(config *JWTConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check access token first
		accessToken := c.Cookies("access_token")
		if accessToken != "" {
			claims, err := validateToken(accessToken, config.SecretKey)
			if err == nil && claims.Type == "access" {
				// Valid access token - redirect to home
				return c.Redirect("/")
			}
		}

		// If access token is invalid/expired, check refresh token
		refreshToken := c.Cookies("refresh_token")
		if refreshToken != "" {
			claims, err := validateToken(refreshToken, config.SecretKey)
			if err == nil && claims.Type == "refresh" {
				// Valid refresh token - generate new access token and redirect
				newAccessToken, err := handleTokenRefresh(refreshToken, config)
				if err == nil {
					// Set new access token cookie
					c.Cookie(createCookie("access_token", newAccessToken, config.AccessTokenDuration))
					return c.Redirect("/")
				}
			}
		}

		// No valid tokens found - allow access to auth routes
		return c.Next()
	}
}

// handleTokenRefresh validates refresh token and generates new access token
func handleTokenRefresh(refreshToken string, config *JWTConfig) (string, error) {
	claims, err := validateToken(refreshToken, config.SecretKey)
	if err != nil {
		return "", err
	}

	if claims.Type != "refresh" {
		return "", ErrInvalidToken
	}

	// Generate new access token
	return config.generateToken(claims.ID, claims.AMR, "access", config.AccessTokenDuration)
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
