package handlers

import (
	"strings"

	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
)

func Render(ctx *fiber.Ctx, component templ.Component) error {
	ctx.Set("Content-Type", "text/html")
	return component.Render(ctx.Context(), ctx.Response().BodyWriter())
}

func GetClientValue(ctx *fiber.Ctx) (string, string) {
	// Improved device detection - now returns normalized value
	userAgent := ctx.Get("User-Agent")
	device := detectDevice(userAgent)

	// Get and normalize URL - use proper URL handling
	url := ctx.BaseURL() // Get base URL first

	return device, url
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