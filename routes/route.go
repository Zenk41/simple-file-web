package routes

import (
	"github.com/Zenk41/simple-file-web/handlers"
	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/gofiber/fiber/v2"
)

type HandlerList struct {
	PageHandler       handlers.PageHandler
	ApiHandler        handlers.ApiHandler
	AuthHandler       handlers.AuthHandler
	PublicLinkHandler handlers.PublicLinkHandler
	JwtConfig         *middlewares.JWTConfig
}

func (hl *HandlerList) RoutesRegister(app *fiber.App) {

	// pages auth
	app.Get("/login", middlewares.RedirectIfAuthenticated(hl.JwtConfig), hl.PageHandler.Login)
	app.Get("/register", middlewares.RedirectIfAuthenticated(hl.JwtConfig), hl.PageHandler.Register)

	app.Get("/login/validateotp", middlewares.IsAuthenticated(hl.JwtConfig, false), hl.PageHandler.ValidateOtp)

	// api auth
	auth := app.Group("/api/auth")
	auth.Post("/login", hl.AuthHandler.Login)
	auth.Post("/register", hl.AuthHandler.Register)
	auth.Post("/logout", middlewares.IsAuthenticated(hl.JwtConfig, true), hl.AuthHandler.Logout)

	otp := auth.Group("/otp", middlewares.IsAuthenticated(hl.JwtConfig, false))
	otp.Post("/generate", hl.AuthHandler.GenerateOtp)
	otp.Post("/verify", hl.AuthHandler.VerifyOtp)
	otp.Post("/validate", hl.AuthHandler.ValidateOtp)
	otp.Post("/disable", hl.AuthHandler.DisableOtp)

	// pages publik
	publik := app.Group("/p")
	publik.Get("/:link", hl.PageHandler.PublikLink)

	// home pages
	app.Get("/", middlewares.IsAuthenticated(hl.JwtConfig, true), hl.PageHandler.Home)

	// api
	api := app.Group("/api")
	api.Use(middlewares.IsAuthenticated(hl.JwtConfig, true))
	api.Get("/download", hl.ApiHandler.DownloadObject)
	api.Get("/presigned-url", hl.ApiHandler.OpenObject)
	api.Post("/key", hl.ApiHandler.PostFormKeyS3)
	api.Post("/folders", hl.ApiHandler.CreateFolder)
	api.Delete("/object", hl.ApiHandler.DeleteObject)
	api.Post("/object-rename", hl.ApiHandler.RenameObject)
	api.Post("/upload", hl.ApiHandler.UploadObject)
	api.Get("/downloads", hl.ApiHandler.DownloadObjectsAsZip)

	pLink := api.Group("/p")
	pLink.Put("/:id", hl.PublicLinkHandler.UpdatePublicLink)
	pLink.Post("/", hl.PublicLinkHandler.CreatePublicLink)
	pLink.Delete("/:id", hl.PublicLinkHandler.DeletePublicLink)
	pLink.Post("/val/link/create", hl.PublicLinkHandler.ValidateLinkCreate)
	pLink.Post("/val/link/update", hl.PublicLinkHandler.ValidateLinkUpdate)

	// pages bucket
	bucket := app.Group("/b")
	bucket.Use(middlewares.IsAuthenticated(hl.JwtConfig, true))
	bucket.Get("/:bucket", hl.PageHandler.BucketRoot)
	bucket.Get("/:bucket/*", hl.PageHandler.GetPathObject)

	// key page
	settings := app.Group("/settings", middlewares.IsAuthenticated(hl.JwtConfig, true))
	settings.Get("/key", hl.PageHandler.PostFormKey)
	settings.Get("/links", hl.PageHandler.PublikLinkList)
	settings.Get("/profile", hl.PageHandler.Profile)

	app.Use(hl.PageHandler.NotFound)

}
