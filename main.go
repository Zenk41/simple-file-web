package main

import (
	"log"

	"github.com/Zenk41/simple-file-web/handlers"
	"github.com/Zenk41/simple-file-web/routes"
	"github.com/gofiber/fiber/v2"
)

func main() {
	// Initialize the Fiber app
	app := fiber.New()

	// Initialize page handlers
	pageHandler := handlers.NewPageHandler()

	app.Static("/public", "/public")

	// Define a simple root route to test the setup
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World")
	})

	// Create an instance of HandlerList with the required handlers
	routeInit := routes.HandlerList{
		PageHandler: pageHandler,
	}

	// Register routes
	routeInit.RoutesRegister(app)

	// Start the Fiber app on port 3000 and handle potential errors
	if err := app.Listen(":3000"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
