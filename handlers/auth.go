package handlers

import (
	"log/slog"

	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type AuthHandler interface {
	Login(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	Logout(ctx *fiber.Ctx) error
}

type authHandler struct {
	logger      *slog.Logger
	authService services.AuthService
	validator   *validator.Validate
	jwtConfig   *middlewares.JWTConfig
}

func NewAuthHandler(logger *slog.Logger, authService services.AuthService, validation *validator.Validate, jwtConfig *middlewares.JWTConfig) AuthHandler {
	return &authHandler{logger: logger, authService: authService, validator: validation, jwtConfig: jwtConfig}
}

func (ah *authHandler) Login(ctx *fiber.Ctx) error {
	ah.logger.Info("cookie not found", "message", "login can be processed")
	payload := new(models.LoginPayload)

	if err := ctx.BodyParser(payload); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	// Validate fields using injected validator
	if err := ah.validator.Struct(payload); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Validation failed",
			"error":   err.Error(),
		})
	}

	user, err := ah.authService.ReadUser()
	if user.ID == uuid.Nil || err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":   "error",
			"message":  "user not found or other error",
			"error":    err,
			"redirect": "/login",
		})
	}

	if payload.Email != user.Email {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":   "error",
			"message":  "",
			"error":    "invalid credentials",
			"redirect": "/login",
		})
	}

	// Validate the password (you would typically compare with hashed password from DB)

	if err := user.CheckPassword(payload.Password); err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":   "error",
			"message":  "wrong password",
			"error":    "Invalid credentials",
			"redirect": "/login",
		})
	}

	// Generate both tokens
	accessToken, refreshToken, err := ah.jwtConfig.GenerateTokens(user.ID.String(), user.Password)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "token generation failed",
		})
	}

	// Set both cookies
	middlewares.SetAuthCookies(ctx, accessToken, refreshToken, ah.jwtConfig)

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":        "success",
		"message":       "success login with email:" + user.Email,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"email":         user.Email,
		"redirect":      "/",
	})
}

func (ah *authHandler) Register(ctx *fiber.Ctx) error {
	payload := new(models.RegisterPayload)

	if err := ctx.BodyParser(payload); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	// Validate fields using injected validator
	if err := ah.validator.Struct(payload); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Validation failed",
			"error":   err.Error(),
		})
	}

	// Attempt to create user
	if err := ah.authService.CreateUser(*payload); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to create user",
			"error":   err.Error(),
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status":   "success",
		"message":  "Successfully registered user",
		"redirect": "/",
	})
}

func (ah *authHandler) Logout(ctx *fiber.Ctx) error {
	// Clear all auth cookies
	middlewares.ClearAuthCookies(ctx)

	// Return success response
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Logged out successfully",
	})
}
