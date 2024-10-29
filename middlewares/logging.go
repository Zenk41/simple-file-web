package middlewares

import (
	"log/slog"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
)

// StructuredLogger logs a Fiber HTTP request using slog.
func StructuredLogger() fiber.Handler {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	return func(c *fiber.Ctx) error {
		start := time.Now() // Start timer
		path := c.Path()
		raw := string(c.Request().URI().QueryString())

		// Process request
		err := c.Next()

		// Create log entry fields
		attrs := []slog.Attr{
			slog.String("time", time.Now().Format(time.RFC3339)),
			slog.String("client_ip", c.IP()),
			slog.String("method", c.Method()),
			slog.String("path", path),
			slog.String("proto", string(c.Request().Header.Protocol())),
			slog.Int("status_code", c.Response().StatusCode()),
			slog.String("latency", time.Since(start).String()),
			slog.Int("body_size", len(c.Response().Body())),
		}

		if raw != "" {
			attrs = append(attrs, slog.String("path", path+"?"+raw))
		}

		if err != nil {
			attrs = append(attrs, slog.String("error_message", err.Error()))
			logger.LogAttrs(c.Context(), slog.LevelError, "Request failed", attrs...)
		} else {
			logger.LogAttrs(c.Context(), slog.LevelInfo, "Request succeeded", attrs...)
		}

		return err
	}
}


func ConfigureLogger(env string) *slog.Logger {
	var handler slog.Handler

	if env == "production" {
			handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
					Level: slog.LevelInfo, // Only log INFO level and above in production
			})
	} else {
			handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
					Level: slog.LevelDebug, // Log everything, including DEBUG, in development
			})
	}

	logger := slog.New(handler)
	return logger
}