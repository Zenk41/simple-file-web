package main

import (
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"
	"time"

	// "strings"

	"github.com/Zenk41/simple-file-web/config"
	"github.com/Zenk41/simple-file-web/handlers"
	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/routes"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/Zenk41/simple-file-web/validation"
	"github.com/robfig/cron/v3"

	"github.com/gofiber/fiber/v2"
)

func main() {

	// setup config
	v := config.SetupViper()
	port := v.GetString("PORT")

	// Initialize the Fiber app
	app := fiber.New(fiber.Config{
		BodyLimit: 1024 * 1024 * 1024, // 1GB
	})

	// Get ORIGIN_URL from config
	originURL := v.GetString("ORIGIN_URL")

	// Use the new CORS middleware
	app.Use(middlewares.NewCORS(middlewares.CORSConfig{
		AllowOrigins: originURL,
	}))

	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Cross-Origin-Opener-Policy", "same-origin")
		return c.Next()
	})

	exp, err := strconv.Atoi(v.GetString("DOWNLOAD_URL_EXPIRATION"))
	if err != nil {
		exp = 3600 //deffault value of expiration delete
	}

	logger := middlewares.ConfigureLogger(v.GetString("APP_ENV"))

	authService := services.NewAuthService(logger, "db_user.json")
	publikLinkService := services.NewDataPublic(logger, "db_publik_link.json")
	s3Service, err := services.NewS3Service(time.Duration(exp)*time.Second, logger)

	if err != nil {
		fmt.Println(err)
	}

	// setup admin user
	if u, _ := authService.ReadUsers(); len(u) < 1 {
		err = authService.CreateAdmin(
			models.RegisterPayload{
				Username: v.GetString("USERNAME_ADMIN"),
				Email:    v.GetString("EMAIL_ADMIN"),
				Password: v.GetString("PASSWORD_ADMIN"),
			},
		)
	}

	if err != nil {
		log.Fatalf("Failed to create admin please input the require env for admin, err: %v", err)
	} else {
		logger.Info("success create admin")
	}

	config.GoogleConfig(
		v.GetString("GOOGLE_CLIENT_ID"),
		v.GetString("GOOGLE_CLIENT_SECRET"),
		fmt.Sprintf(`%s/api/oauth/register/callback`, getFirstURL(originURL)),
		fmt.Sprintf(`%s/api/oauth/login/callback`, getFirstURL(originURL)),
	)

	jwtConfig := middlewares.NewJWTConfig(v.GetString("SECRET_KEY_JWT"))

	authValidation := validation.NewAuthValidator()
	s3Validation := validation.NewS3Validator()
	publicLinkValidation := validation.NewPublicLinkValidator()

	authHandler := handlers.NewAuthHandler(logger, authService, authValidation, jwtConfig, getFirstURL(originURL))
	pageHandler := handlers.NewPageHandler(s3Service, authService, logger, publikLinkService, jwtConfig)
	apiHandler := handlers.NewApiHandler(s3Service, logger, s3Validation)
	publicLinkHandler := handlers.NewPublicLinkHandler(publikLinkService, authService, s3Service, logger, publicLinkValidation)
	oauthHandler := handlers.NewOauthHandler(logger, authService, jwtConfig, config.AppConfig)

	app.Use(middlewares.StructuredLogger())

	app.Static("/public/globals.css", "/public/globals.css")
	app.Static("/public/flowbite.min.js", "/app/node_modules/flowbite/dist/flowbite.min.js")
	app.Static("/public/alpine.js", "/app/node_modules/alpinejs/dist/cdn.min.js")
	app.Static("/public/qrcode.js", "/app/node_modules/qrcode-generator/qrcode.js", fiber.Static{})

	routeInit := routes.HandlerList{
		PageHandler:       pageHandler,
		ApiHandler:        apiHandler,
		AuthHandler:       authHandler,
		PublicLinkHandler: publicLinkHandler,
		JwtConfig:         jwtConfig,
		OauthHandler:      oauthHandler,
	}

	c := cron.New()

	// Schedule a job to run every midnight
	_, err = c.AddFunc("0 0 * * *", func() {
		num := oauthHandler.DeleteExpireState()
		slog.Info("Cron State", slog.Int("Deleted state", num))
	})
	if err != nil {
		fmt.Println("Error scheduling the job:", err)
		return
	}

	// Start the cron scheduler in a goroutine
	go func() {
		c.Start()
	}()

	// Register routes
	routeInit.RoutesRegister(app)

	// Start the Fiber app on port 3000 and handle potential errors
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}

func getFirstURL(originURL string) string {
	urls := strings.Split(originURL, ",")
	if len(urls) > 0 {
		return strings.TrimSpace(urls[0])
	}
	return ""
}
