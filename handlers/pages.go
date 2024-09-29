package handlers

import (
	views_auth "github.com/Zenk41/simple-file-web/views/auth"
	"github.com/gofiber/fiber/v2"
)

type PageHandler interface {
	Login(ctx *fiber.Ctx) error
}
type pageHandler struct{}

func NewPageHandler() PageHandler {
	return &pageHandler{}
}

func (ph *pageHandler) Login(ctx *fiber.Ctx) error {
	return Render(ctx, views_auth.Login())
}
