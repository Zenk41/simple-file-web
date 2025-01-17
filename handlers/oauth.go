package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Zenk41/simple-file-web/config"
	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/gofiber/fiber/v2"
)

type OauthHandler interface {
	CallbackRegister(ctx *fiber.Ctx) error
	CallbackLogin(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	DeleteExpireState() int
}

type oauthHandler struct {
	logger       *slog.Logger
	storeState   []models.StateOauth
	authService  services.AuthService
	googleConfig config.Config
	jwtConfig    *middlewares.JWTConfig
}

func NewOauthHandler(logger *slog.Logger, authService services.AuthService, jwtConfig *middlewares.JWTConfig, googleConfig config.Config) OauthHandler {
	return &oauthHandler{
		logger:       logger,
		storeState:   []models.StateOauth{},
		authService:  authService,
		googleConfig: googleConfig,
		jwtConfig:    jwtConfig,
	}
}

func (oh *oauthHandler) CallbackRegister(ctx *fiber.Ctx) error {
	state := ctx.Query("state")
	err := oh.StateValid(state)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "state error",
			"error":   err,
		})
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Authorization code is missing",
		})
	}

	token, err := oh.googleConfig.GoogleOauthConfigRegister.Exchange(context.Background(), code)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Code-Token Exchange Failed",
			"error":   err,
		})
	}

	agent := fiber.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	_, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "User Data Fetch Failed",
			"errs":    errs,
		})
	}
	var googleUser models.GoogleUserInfo
	if err := json.Unmarshal(body, &googleUser); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "User Data Parse Failed",
			"error":   err.Error(),
		})
	}

	// check if exist
	if _, err := oh.authService.OauthUserExists(googleUser); err == nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "user already exists please login with oauth ",
			"error":   "user exists",
		})
	}

	// Attempt to create user
	if err := oh.authService.CreateWithOauth(googleUser); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to create user",
			"error":   err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "success register with oauth",
		"user":    googleUser,
	})
}

func (oh *oauthHandler) CallbackLogin(ctx *fiber.Ctx) error {
	state := ctx.Query("state")
	err := oh.StateValid(state)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "state error",
			"error":   err,
		})
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Authorization code is missing",
		})
	}

	token, err := oh.googleConfig.GoogleOauthConfigLogin.Exchange(context.Background(), code)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Code-Token Exchange Failed",
			"error":   err,
		})
	}

	agent := fiber.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	_, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "User Data Fetch Failed",
			"errs":    errs,
		})
	}

	var googleUser models.GoogleUserInfo
	if err := json.Unmarshal(body, &googleUser); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "User Data Parse Failed",
			"error":   err.Error(),
		})
	}

	user, err := oh.authService.OauthUserExists(googleUser)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "user already exists please register first ",
			"error":   "user exist",
		})
	}

	authMethod := "oauth"
	device, url := GetClientValue(ctx)

	accessToken, refreshToken, err := oh.jwtConfig.GenerateTokens(user.ID.String(),user.IsAdmin, false, user.OtpEnabled, authMethod, device, url)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "token generation failed",
		})
	}

	// Set both cookies
	middlewares.SetAuthCookies(ctx, accessToken, refreshToken, oh.jwtConfig)

	if user.OtpVerified && user.OtpEnabled {
		return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":        "success",
			"message":       "success login with oauth email:" + user.Email,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"email":         user.Email,
			"twoFA_enabled": user.OtpEnabled,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":        "success",
		"message":       "success login with oauth email:" + user.Email,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"email":         user.Email,
		"twoFA_enabled": user.OtpEnabled,
	})

}

func (oh *oauthHandler) Login(ctx *fiber.Ctx) error {
	state := oh.AddState()
	url := config.AppConfig.GoogleOauthConfigLogin.AuthCodeURL(state.State)
	return ctx.Redirect(url, http.StatusSeeOther)
}
func (oh *oauthHandler) Register(ctx *fiber.Ctx) error {
	state := oh.AddState()
	url := config.AppConfig.GoogleOauthConfigRegister.AuthCodeURL(state.State)
	return ctx.Redirect(url, http.StatusSeeOther)
}

func (oh *oauthHandler) AddState() models.StateOauth {
	b := make([]byte, 16)
	rand.Read(b)
	stateCode := base64.URLEncoding.EncodeToString(b)
	state := models.StateOauth{
		State:     stateCode,
		CreatedAt: time.Now(),
		ExpireAt:  time.Now().Add(15 * time.Hour),
	}
	oh.SaveState(state)
	return state
}

func (oh *oauthHandler) SaveState(state models.StateOauth) {
	oh.storeState = append(oh.storeState, state)
}

func (oh *oauthHandler) StateExists(state string) models.StateOauth {
	for _, s := range oh.storeState {
		if state == s.State {
			return s
		}
	}
	return models.StateOauth{}
}

func (oh *oauthHandler) StateValid(state string) error {
	s := oh.StateExists(state)
	if s.State == "" {
		return fmt.Errorf("state not exists")
	}
	currentTime := time.Now()
	if currentTime.After(s.ExpireAt) {
		return fmt.Errorf("state is not valid")
	}
	oh.DeleteState(s.State)
	return nil
}

func (oh *oauthHandler) DeleteState(state string) {
	for i, s := range oh.storeState {
		if s.State == state {
			oh.storeState = append(oh.storeState[:i], oh.storeState[i+1:]...)
			return
		}
	}
}

func (oh *oauthHandler) DeleteExpireState() int {
	num := 0
	for i, s := range oh.storeState {
		if s.ExpireAt.After(time.Now()) {
			oh.storeState = append(oh.storeState[:i], oh.storeState[i+1:]...)
			num++
		}
	}
	return num
}
