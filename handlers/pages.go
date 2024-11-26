package handlers

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"log/slog"

	"github.com/Zenk41/simple-file-web/middlewares"
	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	views_auth "github.com/Zenk41/simple-file-web/views/auth"
	"github.com/Zenk41/simple-file-web/views/components"
	"github.com/Zenk41/simple-file-web/views/error_handling"
	"github.com/Zenk41/simple-file-web/views/home"
	views_otp "github.com/Zenk41/simple-file-web/views/otp"
	"github.com/Zenk41/simple-file-web/views/public"
	"github.com/Zenk41/simple-file-web/views/public_link"
	views_settings "github.com/Zenk41/simple-file-web/views/settings"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type PageHandler interface {
	NotFound(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	Register(ctx *fiber.Ctx) error
	ValidateOtp(ctx *fiber.Ctx) error
	Profile(ctx *fiber.Ctx) error
	PostFormKey(ctx *fiber.Ctx) error

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
	jwtConfig   *middlewares.JWTConfig
	logger      *slog.Logger
}

func NewPageHandler(s3Service services.S3Service,
	authService services.AuthService,
	logger *slog.Logger,
	pubLink services.PublicLinkManager,
	jwtConfig *middlewares.JWTConfig) PageHandler {
	return &pageHandler{
		s3Service:   s3Service,
		authService: authService, logger: logger, pubLink: pubLink,
		jwtConfig: jwtConfig}
}

func (ph *pageHandler) Login(ctx *fiber.Ctx) error {
	ph.logger.Info("user attempting to log in")

	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, views_auth.Login(models.Alert{Type: typ, Message: message}))
	}
	return Render(ctx, views_auth.Login(models.Alert{}))
}

func (ph *pageHandler) Register(ctx *fiber.Ctx) error {
	user, err := ph.authService.ReadUser()
	if user.ID != uuid.Nil && err == nil {
		ph.logger.Info("User already exists, registration disabled", "message", err)
		return ctx.Redirect("/login?message=Registration is not available for existing users&type=warning")
	}

	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, views_auth.Register(models.Alert{Type: typ, Message: message}))
	}

	return Render(ctx, views_auth.Register(models.Alert{}))
}

func (ph *pageHandler) ValidateOtp(ctx *fiber.Ctx) error {

	claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	if claim.TwoFAVerified {
		return ctx.Redirect("/?message=Access already granted&type=warning")
	}
	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, views_otp.ValidationIndex(models.Alert{Type: typ, Message: message}, models.User{}))
	}

	return Render(ctx, views_otp.ValidationIndex(models.Alert{}, models.User{}))
}

func (ph *pageHandler) Profile(ctx *fiber.Ctx) error {

	claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	user, err := ph.authService.ReadUserWithId(claim.ID)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "cannot read user",
			"error":   err.Error(),
		})
	}

	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, views_settings.Profile(models.Alert{Type: typ, Message: message}, user))
	}

	return Render(ctx, views_settings.Profile(models.Alert{}, user))
}

func (ph *pageHandler) NotFound(ctx *fiber.Ctx) error {
	return Render(ctx, error_handling.NotFound())
}

func (ph *pageHandler) PostFormKey(ctx *fiber.Ctx) error {

	claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	// Retrieve user by ID from the token claims
	user, err := ph.authService.ReadUserWithId(claim.ID)
	if err != nil {
		ph.logger.Info("Failed to retrieve user information", "error", err)
		return ctx.Redirect("/login?message=Unable to retrieve user data. Please try again.&type=warning")
	}

	// Read S3 configuration
	cfg := ph.s3Service.ReadConfig(ctx.Context())

	// load pages with alert success
	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, views_settings.ApiKey(models.Alert{Type: typ, Message: message}, user, cfg))
	}
	return Render(ctx, views_settings.ApiKey(models.Alert{}, user, cfg))
}

func (ph *pageHandler) Home(ctx *fiber.Ctx) error {

	claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	// Retrieve user by ID from the token claims
	user, err := ph.authService.ReadUserWithId(claim.ID)
	if err != nil {
		ph.logger.Info("Failed to retrieve user information", "error", err)
		return ctx.Redirect("/login?message=Unable to retrieve user data. Please try again.&type=warning")
	}

	if ph.s3Service.IsS3ConfigEmpty() {
		ph.logger.Warn("S3 configuration is empty")
		return ctx.Redirect("/settings/key?message=S3 configuration is missing. Please configure your S3 settings.&type=warning")
	}

	str, err := ph.s3Service.ListBucket(ctx.UserContext())
	if err != nil {
		ph.logger.Error("Failed to list buckets", slog.String("error", err.Error()))
		return Render(ctx, error_handling.CannotListBucket(user))
	}

	bucketList := strings.Join(str, ", ")
	ph.logger.Info("Successfully listed buckets", slog.String("buckets", bucketList))

	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, home.Index(models.Alert{Type: typ, Message: message}, user, components.BucketList(str)))
	}
	return Render(ctx, home.Index(models.Alert{}, user, components.BucketList(str)))
}

func (ph *pageHandler) BucketRoot(ctx *fiber.Ctx) error {

	claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	// Retrieve user by ID from the token claims
	user, err := ph.authService.ReadUserWithId(claim.ID)
	if err != nil {
		ph.logger.Info("Failed to retrieve user information", "error", err)
		return ctx.Redirect("/login?message=Unable to retrieve user data. Please try again.&type=warning")
	}

	if ph.s3Service.IsS3ConfigEmpty() {
		ph.logger.Warn("S3 configuration is empty")
		return ctx.Redirect("/settings/key?message=S3 configuration is missing. Please configure your S3 settings.&type=warning")
	}

	bucket := ctx.Params("bucket")
	ph.logger.Info("Listing files for bucket", slog.String("bucket", bucket))

	strFile, strFolder, err := ph.s3Service.ListPageFiles(ctx.Context(), bucket, "")
	if err != nil {
		ph.logger.Error("Failed to list page files", slog.String("bucket", bucket), slog.String("error", err.Error()))
		return Render(ctx, home.Index(models.Alert{}, user, nil))
	}

	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, home.Index(models.Alert{Type: typ, Message: message}, user, components.ListObject([]string{bucket}, strFile, strFolder)))
	}

	return Render(ctx, home.Index(models.Alert{}, user, components.ListObject([]string{bucket}, strFile, strFolder)))
}

func (ph *pageHandler) GetPathObject(ctx *fiber.Ctx) error {
	claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	// Retrieve user by ID from the token claims
	user, err := ph.authService.ReadUserWithId(claim.ID)
	if err != nil {
		ph.logger.Info("Failed to retrieve user information", "error", err)
		return ctx.Redirect("/login?message=Unable to retrieve user data. Please try again.&type=warning")
	}

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

	ph.logger.Info("Accessing path objects", slog.String("bucket", bucket), slog.String("path", path))
	p := []string{bucket}
	p = append(p, strings.Split(decodedPath, "/")...)

	message := ctx.Query("message")
	typ := ctx.Query("type")
	if message != "" && typ != "" {
		return Render(ctx, home.Index(models.Alert{Type: typ, Message: message}, user, components.ListObject(p, files, folders)))
	}

	return Render(ctx, home.Index(models.Alert{}, user, components.ListObject(p, files, folders)))
}

func (ph *pageHandler) PublikLink(ctx *fiber.Ctx) error {
	var user models.User
	isLogin := false

	if claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token")); err == nil {
		user, err = ph.authService.ReadUserWithId(claim.ID)
		if err != nil {
			ph.logger.Info("Failed to retrieve user information", "error", err)
		}
		isLogin = true
	}

	link := ctx.Params("link")
	ph.logger.Info("Listing public object with link", slog.String("link", link))

	res, err := ph.pubLink.GetRootByLink(link)
	if err != nil {
		ph.logger.Error("Failed to get link or link not available",
			slog.String("bucket", link),
			slog.String("error", err.Error()))
		return Render(ctx, error_handling.NotFound())
	}

	if res.Privacy == "PRIVATE" {
		key := ctx.Query("access-key")
		if key == "" {
			return Render(ctx, error_handling.InvalidKeyAccesing(models.Alert{Type: "warning", Message: "access key empty"}))
		}
		if res.AccessKey != key {
			return Render(ctx, error_handling.InvalidKeyAccesing(models.Alert{Type: "error", Message: "access key not valid"}))
		}
	}

	files, _, err := ph.s3Service.ListPageFiles(
		ctx.Context(),
		res.RealRootBucket+"/",
		res.RealRootPath+"/",
	)
	if err != nil {
		ph.logger.Error("Failed to list page files by link",
			slog.String("bucket", res.RealRootBucket),
			slog.String("decodedPath", res.RealRootPath),
			slog.String("error", err.Error()))
	}

	ph.logger.Info("Accessing path objects with publik link",
		slog.String("bucket", res.RealRootBucket),
		slog.String("path", res.RealRootPath),
		slog.String("link", link))

	pathComponents := append([]string{res.RealRootBucket}, strings.Split(res.RealRootPath, "/")...)

	message := ctx.Query("message")
	typ := ctx.Query("type")

	if message != "" && typ != "" {
		return Render(ctx, public.Index(
			models.Alert{Type: typ, Message: message},
			user,
			public.ListObject(pathComponents, files, link),
			isLogin,
		))
	}

	return Render(ctx, public.Index(
		models.Alert{},
		user,
		public.ListObject(pathComponents, files, link),
		isLogin,
	))
}

func (ph *pageHandler) PublikLinkList(ctx *fiber.Ctx) error {
	claim, err := ph.jwtConfig.DecodeToken(ctx.Cookies("access_token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "failed to decode token",
			"error":   err.Error(),
		})
	}

	// Retrieve user by ID from the token claims
	user, err := ph.authService.ReadUserWithId(claim.ID)
	if err != nil {
		ph.logger.Info("Failed to retrieve user information", "error", err)
		return ctx.Redirect("/login?message=Unable to retrieve user data. Please try again.&type=warning")
	}

	if ph.s3Service.IsS3ConfigEmpty() {
		ph.logger.Warn("S3 configuration is empty")
		return ctx.Redirect("/settings/key?message=S3 configuration is missing. Please configure your S3 settings.&type=warning")
	}

	links := ph.pubLink.ReadPublicLinks()
	if links == nil {
		ph.logger.Warn("links is empty")
		return Render(ctx, public_link.Index(nil, models.Alert{Type: "warning", Message: "links is empty"}, user, nil, 0, 0, 0, 0, 0))
	}

	pageStr := ctx.Query("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	const itemsPerPage = 5
	totalItems := len(links)
	totalPages := int(math.Ceil(float64(totalItems) / float64(itemsPerPage)))

	message := ctx.Query("message")
	typ := ctx.Query("type")

	// Ensure the page value is within the valid range
	if totalPages > 0 && page > totalPages {
		page = totalPages
		redirectURL := fmt.Sprintf("/settings/links?page=%d", page)
		if message != "" && typ != "" {
			redirectURL += fmt.Sprintf("&message=%s&type=%s", message, typ)
		}
		return ctx.Redirect(redirectURL)
	} else if totalPages == 0 {
		page = 1 // Set default page if there are no items
	}
	// Calculate start and end index for current page
	startIndex := (page - 1) * itemsPerPage
	endIndex := min(startIndex+itemsPerPage, totalItems)
	// Get current page links
	currentLinks := links[startIndex:endIndex]

	bucketData := make(map[string][]string)

	// List all buckets
	buckets, _ := ph.s3Service.ListBucket(ctx.Context())
	for _, bucket := range buckets {
		folders, err := ph.s3Service.ListFolder(ctx.Context(), bucket, "")
		if err != nil {
			continue
		}
		bucketData[bucket] = folders
	}

	if message != "" && typ != "" {
		return Render(ctx, public_link.Index(bucketData, models.Alert{Type: typ, Message: message}, user, currentLinks, page, startIndex, endIndex, totalPages, totalItems))
	}

	return Render(ctx, public_link.Index(bucketData, models.Alert{}, user, currentLinks, page, startIndex, endIndex, totalPages, totalItems))
}
