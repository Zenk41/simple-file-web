package middlewares

import (
	"github.com/gofiber/fiber/v2"
	"strings"
)

// CORSConfig holds the configuration for CORS
type CORSConfig struct {
	AllowOrigins string
}

// NewCORS creates a new CORS middleware with the given config
func NewCORS(config CORSConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")
		allowedOrigins := strings.Split(config.AllowOrigins, ",")
		
		// Check if the origin is allowed
		isAllowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == strings.TrimSpace(allowedOrigin) || allowedOrigin == "*" {
				isAllowed = true
				break
			}
		}

		// If origin is allowed, set CORS headers
		if isAllowed {
			c.Set("Access-Control-Allow-Origin", origin)
		} else {
			// If origin is not in the allowed list, default to the first allowed origin
			c.Set("Access-Control-Allow-Origin", strings.TrimSpace(allowedOrigins[0]))
		}

		// Set other CORS headers
		c.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		c.Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if c.Method() == "OPTIONS" {
			return c.SendStatus(fiber.StatusNoContent)
		}

		return c.Next()
	}
}