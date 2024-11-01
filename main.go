package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	// "strings"

	"github.com/Zenk41/simple-file-web/config"
	"github.com/Zenk41/simple-file-web/handlers"
	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/Zenk41/simple-file-web/routes"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/Zenk41/simple-file-web/validation"

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

	jwtConfig := middlewares.NewJWTConfig(v.GetString("SECRET_KEY_JWT"))

	authValidation := validation.NewAuthValidator()
	s3Validation := validation.NewS3Validator()

	authHandler := handlers.NewAuthHandler(logger, authService, authValidation, jwtConfig)
	pageHandler := handlers.NewPageHandler(s3Service, authService, logger, publikLinkService)
	apiHandler := handlers.NewApiHandler(s3Service, logger, s3Validation)

	app.Use(middlewares.StructuredLogger())

	app.Static("/public", "/public")
	app.Static("/public/flowbite.min.js", "./node_modules/flowbite/dist/flowbite.min.js")
	app.Static("/public/alpinejs", "./node_modules/alpinejs/dist/cdn.min.js")

	routeInit := routes.HandlerList{
		PageHandler: pageHandler,
		ApiHandler:  apiHandler,
		AuthHandler: authHandler,
		JwtConfig:   jwtConfig,
	}

	// Register routes
	routeInit.RoutesRegister(app)

	// Start the Fiber app on port 3000 and handle potential errors

	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
