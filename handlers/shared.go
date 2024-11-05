package handlers

import (
	"github.com/Zenk41/simple-file-web/models"
	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
)

func Render(ctx *fiber.Ctx, component templ.Component) error {
	ctx.Set("Content-Type", "text/html")
	return component.Render(ctx.Context(), ctx.Response().BodyWriter())
}


var OnBoarding models.OnBoarding
