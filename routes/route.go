package routes

import (

	"github.com/Zenk41/simple-file-web/handlers"
	"github.com/gofiber/fiber/v2"
)

type HandlerList struct {
	PageHandler handlers.PageHandler
	ApiHandler  handlers.ApiHandler
	AuthHandler handlers.AuthHandler
}

func (hl *HandlerList) RoutesRegister(app *fiber.App) {

	// home pages
	app.Get("/", hl.PageHandler.Home)

	// pages auth
	app.Get("/login", hl.PageHandler.Login)
	app.Get("/register", hl.PageHandler.Register)

	

	// pages bucket
	app.Get("/b/:bucket", hl.PageHandler.BucketRoot)
	app.Get("/b/:bucket/*", hl.PageHandler.GetPathObject)
	app.Get("/p/:link", hl.PageHandler.PublikLink)

	app.Get("/boarding", hl.PageHandler.OnBoarding)

	// api
	
	app.Get("/api/download", hl.ApiHandler.DownloadObject)
	app.Get("/api/presigned-url", hl.ApiHandler.OpenObject)
	app.Post("/api/key", hl.ApiHandler.PostFormKeyS3)
	app.Post("/api/folders", hl.ApiHandler.CreateFolder)
	app.Delete("/api/object", hl.ApiHandler.DeleteObject)
	app.Post("/api/object-rename", hl.ApiHandler.RenameObject)
	app.Post("/api/upload", hl.ApiHandler.UploadObject)
	app.Get("/api/downloads", hl.ApiHandler.DownloadObjectsAsZip)

	// api auth
	app.Post("/api/auth/login", hl.AuthHandler.Login)
	// app.Post("/api/auth/register")
	// app.Post("/api/auth/login")
	// app.Post("/api/auth/otp/generate")
	// app.Post("/api/auth/otp/verify")
	// app.Post("/api/auth/otp/validate")
	

}
