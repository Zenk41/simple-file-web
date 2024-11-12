package handlers

import (
	"log/slog"

	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type AuthHandler interface {
	Login(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	Logout(ctx *fiber.Ctx) error
	GenerateOtp(ctx *fiber.Ctx) error
	VerifyOtp(ctx *fiber.Ctx) error
	ValidateOtp(ctx *fiber.Ctx) error
	DisableOtp(ctx *fiber.Ctx) error
}

type authHandler struct {
	logger      *slog.Logger
	authService services.AuthService
	validator   *validator.Validate
	jwtConfig   *middlewares.JWTConfig
	Issuer      string
}

func NewAuthHandler(logger *slog.Logger, authService services.AuthService, validation *validator.Validate, jwtConfig *middlewares.JWTConfig, Issuer string) AuthHandler {
	return &authHandler{logger: logger, authService: authService, validator: validation, jwtConfig: jwtConfig, Issuer: Issuer}
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

	// Define values for authMethod, device, and url
	authMethod := "password"
	device, url := GetClientValue(ctx)

	accessToken, refreshToken, err := ah.jwtConfig.GenerateTokens(user.ID.String(), false, user.OtpEnabled, authMethod, device, url)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "token generation failed",
		})
	}

	// Set both cookies
	middlewares.SetAuthCookies(ctx, accessToken, refreshToken, ah.jwtConfig)

	if user.OtpVerified && user.OtpEnabled {
		return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":        "success",
			"message":       "success login with email:" + user.Email,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"email":         user.Email,
			"twoFA_enabled": user.OtpEnabled,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":        "success",
		"message":       "success login with email:" + user.Email,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"email":         user.Email,
		"twoFA_enabled": user.OtpEnabled,
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
		"status":  "success",
		"message": "Successfully registered user",
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

func (ah *authHandler) GenerateOtp(ctx *fiber.Ctx) error {

	claim, err := ah.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	if claim.TwoFAVerified {
		return ctx.Redirect("/")
	}

	user, err := ah.authService.ReadUserWithId(claim.ID)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "cannot read user",
			"error":   err.Error(),
		})
	}

	if user.OtpEnabled && user.OtpVerified {
		return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "failed to generated",
			"message": "already setup the otp, need to disable to reverify otp",
			"error":   "generating otp is prohibited when otp is enabled",
		})
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      ah.Issuer,
		AccountName: user.Email,
		SecretSize:  15,
	})

	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to generate otp",
			"error":   err.Error(),
		})
	}

	ah.authService.UpdateOTP(models.User{
		OtpSecret:  key.Secret(),
		OtpAuthUrl: key.URL(),
	})

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":       "success",
		"message":      "otp is generated",
		"base32":       key.Secret(),
		"otp_auth_url": key.URL(),
	})
}

func (ah *authHandler) VerifyOtp(ctx *fiber.Ctx) error {
	payload := new(models.OTPInput)

	if err := ctx.BodyParser(payload); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	claim, err := ah.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	user, err := ah.authService.ReadUserWithId(claim.ID)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "cannot read user",
			"error":   err.Error(),
		})
	}

	valid := totp.Validate(payload.Token, user.OtpSecret)
	if !valid {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "token is invalid",
			"error":   "token is invalid",
		})
	}
	user.OtpEnabled = true
	user.OtpVerified = true
	err = ah.authService.EnablingOTP(user)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "cannot enabling otp",
			"error":   err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"otp_verified": true,
		"user": fiber.Map{"status": "success",
			"message":     "otp is generated",
			"id":          user.ID,
			"username":    user.Username,
			"email":       user.Email,
			"otp_enabled": user.OtpEnabled},
	})
}
func (ah *authHandler) ValidateOtp(ctx *fiber.Ctx) error {
	payload := new(models.OTPInput)

	if err := ctx.BodyParser(&payload); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	claim, err := ah.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	user, err := ah.authService.ReadUserWithId(claim.ID)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "cannot read user",
			"error":   err.Error(),
		})
	}

	valid := totp.Validate(payload.Token, user.OtpSecret)
	if !valid {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "token is invalid",
			"error":   "token is invalid",
		})
	}

	authMethod := "password-with-otp"
	device, url := GetClientValue(ctx)

	accessToken, refreshToken, err := ah.jwtConfig.GenerateTokens(user.ID.String(), true, user.OtpEnabled, authMethod, device, url)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "token generation failed",
		})
	}

	middlewares.SetAuthCookies(ctx, accessToken, refreshToken, ah.jwtConfig)

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"otp_valid": true,
	})

}

func (ah *authHandler) DisableOtp(ctx *fiber.Ctx) error {
	claim, err := ah.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	user, err := ah.authService.ReadUserWithId(claim.ID)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "cannot read user",
			"error":   err.Error(),
		})
	}

	user.OtpEnabled = false
	if err := ah.authService.UpdateUser(user); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "cannot disable otp",
			"error":   err.Error(),
		})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"otp_disabled": true,
		"user": fiber.Map{"status": "success",
			"message":  "otp is disabled",
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email},
	})
}
