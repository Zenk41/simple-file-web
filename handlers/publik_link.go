package handlers

import (
	"log/slog"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type PublicLinkHandler interface {
	CreatePublicLink(ctx *fiber.Ctx) error
	DeletePublicLink(ctx *fiber.Ctx) error
	UpdatePublicLink(ctx *fiber.Ctx) error
}

type publicLinkHandler struct {
	publicLinkService services.PublicLinkManager
	authService       services.AuthService
	validator         *validator.Validate
	logger            *slog.Logger
}

func NewPublicLinkHandler(pLinkService services.PublicLinkManager, authService services.AuthService, logger *slog.Logger, validator *validator.Validate) PublicLinkHandler {
	return &publicLinkHandler{
		publicLinkService: pLinkService,
		authService:       authService,
		logger:            logger,
		validator:         validator,
	}
}

func (plh *publicLinkHandler) CreatePublicLink(ctx *fiber.Ctx) error {
	payload := new(models.PayloadPublicLink)

	if err := ctx.BodyParser(payload); err != nil {
		plh.logger.Error("Invalid request body", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	if err := plh.validator.Struct(payload); err != nil {
		plh.logger.Error("Validation failed", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Validation failed",
			"error":   err.Error(),
		})
	}

	link := models.PublicLink{
		Link:           payload.Link,
		RealRootBucket: payload.RealRootBucket,
		RealRootPath:   payload.RealRootPath,
		AccessKey:      payload.AccessKey,
		AccessType:     payload.AccessType,
		Privacy:        payload.Privacy,
	}

	if err := plh.publicLinkService.CreatePublicLink(link); err != nil {
		plh.logger.Error("failed to create public link", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to create public link",
			"error":   err.Error(),
		})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "success create a public link ",
	})
}

func (plh *publicLinkHandler) DeletePublicLink(ctx *fiber.Ctx) error {
	id := ctx.Query("id")
	if id == "" {
		plh.logger.Error("id cannot be empty", slog.String("error", "id is empty"))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to delete public link",
			"error":   "id cannot be empty",
		})
	}
	if err := plh.publicLinkService.DeletePublicLink(id); err != nil {
		plh.logger.Error("failed to delete public link", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to delete public link",
			"error":   err.Error(),
		})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "success delete a public link with id" + id,
	})
}

func (plh *publicLinkHandler) UpdatePublicLink(ctx *fiber.Ctx) error {
	id := ctx.Query("id")
	if id == "" {
		plh.logger.Error("id cannot be empty", slog.String("error", "id is empty"))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to update public link",
			"error":   "id cannot be empty",
		})
	}
	payload := new(models.PayloadPublicLink)

	if err := ctx.BodyParser(payload); err != nil {
		plh.logger.Error("Invalid request body", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	if err := plh.validator.Struct(payload); err != nil {
		plh.logger.Error("Validation failed", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Validation failed",
			"error":   err.Error(),
		})
	}

	link := models.PublicLink{
		Link:           payload.Link,
		RealRootBucket: payload.RealRootBucket,
		RealRootPath:   payload.RealRootPath,
		AccessKey:      payload.AccessKey,
		AccessType:     payload.AccessType,
		Privacy:        payload.Privacy,
	}

	if err := plh.publicLinkService.UpdatePublicLink(id, link); err != nil {
		plh.logger.Error("failed to update public link", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to update public link",
			"error":   err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "success update a public link with id" + id,
	})
}
