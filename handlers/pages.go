package handlers

import (
	"net/url"
	"strings"

	"log/slog"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	views_auth "github.com/Zenk41/simple-file-web/views/auth"
	"github.com/Zenk41/simple-file-web/views/components"
	"github.com/Zenk41/simple-file-web/views/error_handling"
	"github.com/Zenk41/simple-file-web/views/home"
	"github.com/Zenk41/simple-file-web/views/on_boarding"
	"github.com/Zenk41/simple-file-web/views/public"
	"github.com/Zenk41/simple-file-web/views/public_link"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type PageHandler interface {
	NotFound(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	PostFormKey(ctx *fiber.Ctx) error
	OnBoarding(ctx *fiber.Ctx) error
	Home(ctx *fiber.Ctx) error
	BucketRoot(ctx *fiber.Ctx) error
	GetPathObject(ctx *fiber.Ctx) error
	PublikLink(ctx *fiber.Ctx) error
	PublikLinkList(ctx *fiber.Ctx) error
}

type pageHandler struct {
	s3Service   services.S3Service
	authService services.AuthService
	pubLink     services.PublicLinkManager
	logger      *slog.Logger
}

func NewPageHandler(s3Service services.S3Service, authService services.AuthService, logger *slog.Logger, pubLink services.PublicLinkManager) PageHandler {
	return &pageHandler{s3Service: s3Service,
		authService: authService, logger: logger, pubLink: pubLink}
}

func (ph *pageHandler) Login(ctx *fiber.Ctx) error {
	ph.logger.Info("user attempting to log in")
	return Render(ctx, views_auth.Login())
}

func (ph *pageHandler) Register(ctx *fiber.Ctx) error {
	user, err := ph.authService.ReadUser()
	if user.ID != uuid.Nil && err == nil {
		ph.logger.Info("user already exist cant do register", "message", err)
		return ctx.Redirect("/login")
	}

	return Render(ctx, views_auth.Register())
}

func (ph *pageHandler) OnBoarding(ctx *fiber.Ctx) error {
	if !OnBoarding.Ob1.IsDone {
		return Render(ctx, on_boarding.Ob1())
	}
	if !OnBoarding.Ob2.IsDone {
		return Render(ctx, on_boarding.Ob2())
	}
	if !OnBoarding.Ob3.IsDone {
		return Render(ctx, on_boarding.Ob3())
	}
	ph.logger.Info("onboarding already been done before", "message", "will be redirect to home page")
	return ctx.Redirect("/")
}

func (ph *pageHandler) NotFound(ctx *fiber.Ctx) error {
	return Render(ctx, error_handling.NotFound())
}

func (ph *pageHandler) PostFormKey(ctx *fiber.Ctx) error {
	user, err := ph.authService.ReadUser()
	if err != nil {
		ph.logger.Info("cannot read user", "message", err)
		return ctx.Redirect("/login")
	}
	cfg := ph.s3Service.ReadConfig(ctx.Context())
	return Render(ctx, home.Index(user, components.InputKeysS3(cfg)))
}

func (ph *pageHandler) Home(ctx *fiber.Ctx) error {
	if ph.s3Service.IsS3ConfigEmpty() {
		ph.logger.Warn("S3 configuration is empty")
		return ctx.Redirect("/settings/key")
	}

	user, err := ph.authService.ReadUser()
	if err != nil {
		ph.logger.Info("cannot read user", "message", err)
		return ctx.Redirect("/login")
	}

	str, err := ph.s3Service.ListBucket(ctx.UserContext())
	if err != nil {
		ph.logger.Error("Failed to list buckets", slog.String("error", err.Error()))
		return Render(ctx, error_handling.CannotListBucket(user))
	}

	bucketList := strings.Join(str, ", ")
	ph.logger.Info("Successfully listed buckets", slog.String("buckets", bucketList))
	return Render(ctx, home.Index(user, components.BucketList(str)))
}

func (ph *pageHandler) BucketRoot(ctx *fiber.Ctx) error {
	if ph.s3Service.IsS3ConfigEmpty() {
		ph.logger.Warn("S3 configuration is empty")
		return ctx.Redirect("/settings/key")
	}

	user, err := ph.authService.ReadUser()
	if err != nil {
		ph.logger.Info("cannot read user", "message", err)
		return ctx.Redirect("/login")
	}

	bucket := ctx.Params("bucket")
	ph.logger.Info("Listing files for bucket", slog.String("bucket", bucket))

	strFile, strFolder, err := ph.s3Service.ListPageFiles(ctx.Context(), bucket, "")
	if err != nil {
		ph.logger.Error("Failed to list page files", slog.String("bucket", bucket), slog.String("error", err.Error()))
		return Render(ctx, home.Index(user, nil))
	}

	return Render(ctx, home.Index(user, components.ListObject([]string{bucket}, strFile, strFolder)))
}

func (ph *pageHandler) GetPathObject(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	path := ctx.Params("*")

	decodedPath, err := url.QueryUnescape(path)
	if err != nil {
		ph.logger.Error("Error decoding path", slog.String("path", path), slog.String("error", err.Error()))
	} else {
		ph.logger.Info("Decoded path", slog.String("decodedPath", decodedPath))
	}

	files, folders, err := ph.s3Service.ListPageFiles(ctx.Context(), bucket+"/", decodedPath+"/")
	if err != nil {
		ph.logger.Error("Failed to list page files", slog.String("bucket", bucket), slog.String("decodedPath", decodedPath), slog.String("error", err.Error()))
	}

	user, err := ph.authService.ReadUser()
	if err != nil {
		ph.logger.Info("cannot read user", "message", err)
		return ctx.Redirect("/login")
	}

	ph.logger.Info("Accessing path objects", slog.String("bucket", bucket), slog.String("path", path))
	p := []string{bucket}
	p = append(p, strings.Split(decodedPath, "/")...)
	return Render(ctx, home.Index(user, components.ListObject(p, files, folders)))
}

func (ph *pageHandler) PublikLink(ctx *fiber.Ctx) error {

	if ph.s3Service.IsS3ConfigEmpty() {
		ph.logger.Warn("S3 configuration is empty")
		return Render(ctx, home.Index(models.User{}, components.InputKeysS3(models.ConfigS3{})))
	}

	link := ctx.Params("link")
	ph.logger.Info("Listing public object with link", slog.String("link", link))
	res, err := ph.pubLink.GetRootByLink(link)
	if err != nil {
		ph.logger.Error("Failed to get link or link not available", slog.String("bucket", link), slog.String("error", err.Error()))
		return Render(ctx, error_handling.NotFound())
	}

	files, _, err := ph.s3Service.ListPageFiles(ctx.Context(), res.RealRootBucket+"/", res.RealRootPath+"/")
	if err != nil {
		ph.logger.Error("Failed to list page files by link", slog.String("bucket", res.RealRootBucket), slog.String("decodedPath", res.RealRootPath), slog.String("error", err.Error()))
	}

	user, err := ph.authService.ReadUser()
	if err != nil {
		ph.logger.Info("cannot read user", "message", err)
		return ctx.Redirect("/login")
	}

	ph.logger.Info("Accessing path objects with publik link", slog.String("bucket", res.RealRootBucket), slog.String("path", res.RealRootPath), slog.String("link", link))
	p := []string{res.RealRootBucket}
	p = append(p, strings.Split(res.RealRootPath, "/")...)
	return Render(ctx, public.Index(user, public.ListObject(p, files, link)))
}

func (ph *pageHandler) PublikLinkList(ctx *fiber.Ctx) error {

	if ph.s3Service.IsS3ConfigEmpty() {
		ph.logger.Warn("S3 configuration is empty")
		return ctx.Redirect("/settings/key")
	}

	user, err := ph.authService.ReadUser()
	if err != nil {
		ph.logger.Info("cannot read user", "message", err)
		return ctx.Redirect("/login")
	}

	links := ph.pubLink.ReadPublicLinks()

	return Render(ctx, public_link.Index(user,links))
}

