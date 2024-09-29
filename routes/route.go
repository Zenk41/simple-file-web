package routes

import (
	"fmt"

	"github.com/Zenk41/simple-file-web/handlers"
	"github.com/gofiber/fiber/v2"
)

type HandlerList struct {
	PageHandler handlers.PageHandler
}

func (hl *HandlerList) RoutesRegister(app *fiber.App) {
	fmt.Println("Serving static files from: ", "./public")

	app.Get("/login", hl.PageHandler.Login)
}
