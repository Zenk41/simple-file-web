package routes

import (
	"github.com/Zenk41/simple-file-web/handlers"
	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/gofiber/fiber/v2"
)

type HandlerList struct {
	PageHandler handlers.PageHandler
	ApiHandler  handlers.ApiHandler
	AuthHandler handlers.AuthHandler
	JwtConfig   *middlewares.JWTConfig
}

func (hl *HandlerList) RoutesRegister(app *fiber.App) {

	// pages auth
	app.Get("/login", middlewares.RedirectIfAuthenticated(hl.JwtConfig), hl.PageHandler.Login)
	app.Get("/register", middlewares.RedirectIfAuthenticated(hl.JwtConfig), hl.PageHandler.Register)

	app.Get("/boarding", hl.PageHandler.OnBoarding)

	// api auth
	auth := app.Group("/api/auth")
	auth.Post("/login", hl.AuthHandler.Login)
	auth.Post("/register", hl.AuthHandler.Register)
	auth.Post("/logout", middlewares.IsAuthenticated(hl.JwtConfig), hl.AuthHandler.Logout)
	// app.Post("/api/auth/otp/generate")
	// app.Post("/api/auth/otp/verify")
	// app.Post("/api/auth/otp/validate")

	// pages publik
	publik := app.Group("/p")
	publik.Get("/:link", hl.PageHandler.PublikLink)

	// home pages
	app.Get("/", middlewares.IsAuthenticated(hl.JwtConfig), hl.PageHandler.Home)

	// api
	api := app.Group("/api")
	api.Use(middlewares.IsAuthenticated(hl.JwtConfig))
	api.Get("/download", hl.ApiHandler.DownloadObject)
	api.Get("/presigned-url", hl.ApiHandler.OpenObject)
	api.Post("/key", hl.ApiHandler.PostFormKeyS3)
	api.Post("/folders", hl.ApiHandler.CreateFolder)
	api.Delete("/object", hl.ApiHandler.DeleteObject)
	api.Post("/object-rename", hl.ApiHandler.RenameObject)
	api.Post("/upload", hl.ApiHandler.UploadObject)
	api.Get("/downloads", hl.ApiHandler.DownloadObjectsAsZip)

	// pages bucket
	bucket := app.Group("/b")
	bucket.Use(middlewares.IsAuthenticated(hl.JwtConfig))
	bucket.Get("/:bucket", hl.PageHandler.BucketRoot)
	bucket.Get("/:bucket/*", hl.PageHandler.GetPathObject)

	// key page
	settings := app.Group("/settings", middlewares.IsAuthenticated(hl.JwtConfig))
	settings.Get("/key", hl.PageHandler.PostFormKey)
	settings.Get("/links", hl.PageHandler.PublikLinkList)

	app.Use(hl.PageHandler.NotFound)

}
