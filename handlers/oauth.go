package handlers

import (
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
		oh.logger.Error("invalid state", "error", err)
		return ctx.Redirect("/register?message=invalid state&type=error")
	}

	code := ctx.Query("code")
	if code == "" {
		oh.logger.Error("authorization code is missing")
		return ctx.Redirect("/register?message=authorization code is missing&type=error")
	}

	token, err := oh.googleConfig.GoogleOauthConfigRegister.Exchange(ctx.Context(), code)
	if err != nil {
		oh.logger.Error("code-token exchange failed", "error", err)
		return ctx.Redirect("/register?message=code-token exchange failed&type=error")
	}

	agent := fiber.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	_, body, errs := agent.Bytes()
	if len(errs) > 0 {
		oh.logger.Error("user data fetch failed", "error", errs)
		return ctx.Redirect("/register?message=user data fetch failed&type=error")

	}
	var googleUser models.GoogleUserInfo
	if err := json.Unmarshal(body, &googleUser); err != nil {
		oh.logger.Error("user data parse failed", "error", err)
		return ctx.Redirect("/register?message=user data parse failed&type=error")

	}

	// check if exist
	if _, err := oh.authService.OauthUserExists(googleUser); err == nil {
		oh.logger.Error("user already exists please login", "error", err)
		return ctx.Redirect("/register?message=user already exists please login&type=error")

	}

	// Attempt to create user
	if err := oh.authService.CreateWithOauth(googleUser); err != nil {
		oh.logger.Error("failed to register the user", "error", err)
		return ctx.Redirect("/register?message=failed to register the user&type=error")
	}

	return ctx.Redirect("/login?message=success register with oauth&type=success")
}

func (oh *oauthHandler) CallbackLogin(ctx *fiber.Ctx) error {
	state := ctx.Query("state")
	err := oh.StateValid(state)
	if err != nil {
		oh.logger.Error("invalid state", "error", err)
		return ctx.Redirect("/login?message=invalid state&type=error")
	}

	code := ctx.Query("code")
	if code == "" {
		oh.logger.Error("authorization code is missing")
		return ctx.Redirect("/login?message=authorization code is missing&type=error")
	}

	token, err := oh.googleConfig.GoogleOauthConfigLogin.Exchange(ctx.Context(), code)
	if err != nil {
		oh.logger.Error("code-token exchange failed", "error", err)
		return ctx.Redirect("/login?message=code-token exchange failed&type=error")
	}

	agent := fiber.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	_, body, errs := agent.Bytes()
	if len(errs) > 0 {
		oh.logger.Error("user data fetch failed", "error", errs)
		return ctx.Redirect("/login?message=user data fetch failed&type=error")
	}

	var googleUser models.GoogleUserInfo
	if err := json.Unmarshal(body, &googleUser); err != nil {
		oh.logger.Error("failed to parse user data", "error", errs)
		return ctx.Redirect("/login?message=failed to parse user data&type=error")
	}

	user, err := oh.authService.OauthUserExists(googleUser)
	if err != nil {
		oh.logger.Error("user does not exist please register first", "error", err)
		return ctx.Redirect("/login?message=user does not exist please register first&type=error")
	}

	authMethod := "oauth"
	device, url := GetClientValue(ctx)

	accessToken, refreshToken, err := oh.jwtConfig.GenerateTokens(user.ID.String(), user.IsAdmin, false, user.OtpEnabled, authMethod, device, url)
	if err != nil {
		oh.logger.Error("token generation failed", "error", err)
		return ctx.Redirect("/login?message=token generation failed&type=error")
	}

	// Set both cookies
	middlewares.SetAuthCookies(ctx, accessToken, refreshToken, oh.jwtConfig)
	return ctx.Redirect("/")

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
