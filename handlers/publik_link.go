package handlers

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/Zenk41/simple-file-web/views/error_handling"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type PublicLinkHandler interface {
	CreatePublicLink(ctx *fiber.Ctx) error
	DeletePublicLink(ctx *fiber.Ctx) error
	UpdatePublicLink(ctx *fiber.Ctx) error
	ValidateLinkCreate(ctx *fiber.Ctx) error
	ValidateLinkUpdate(ctx *fiber.Ctx) error

	OpenFile(ctx *fiber.Ctx) error
	DownloadFile(ctx *fiber.Ctx) error
}

type publicLinkHandler struct {
	publicLinkService services.PublicLinkManager
	authService       services.AuthService
	s3Service         services.S3Service
	validator         *validator.Validate
	logger            *slog.Logger
}

func NewPublicLinkHandler(pLinkService services.PublicLinkManager, authService services.AuthService, s3Service services.S3Service, logger *slog.Logger, validator *validator.Validate) PublicLinkHandler {
	return &publicLinkHandler{
		publicLinkService: pLinkService,
		authService:       authService,
		s3Service:         s3Service,
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
		RealRootPath:   strings.Trim(payload.RealRootPath, "/"),
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
	id := ctx.Params("id")
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
	plh.logger.Info("success", slog.String("id", id))
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "success delete a public link with id" + id,
	})
}

func (plh *publicLinkHandler) UpdatePublicLink(ctx *fiber.Ctx) error {
	id := ctx.Params("id")
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
		RealRootPath:   strings.Trim(payload.RealRootPath, "/"),
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

func (plh *publicLinkHandler) ValidateLinkUpdate(ctx *fiber.Ctx) error {
	payload := new(models.ValidateLinkUpdate)

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

	if duplicate := plh.publicLinkService.IsLinkDuplicate(payload.Link, payload.ID); duplicate {
		plh.logger.Error("Validation failed", slog.String("error", "link is duplicate"))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "link is duplicate",
			"error":   "cant use this link, it's duplicate",
		})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "link it's available",
	})
}

func (plh *publicLinkHandler) ValidateLinkCreate(ctx *fiber.Ctx) error {
	payload := new(models.ValidateLinkCreate)

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

	if duplicate := plh.publicLinkService.IsLinkDuplicate(payload.Link, ""); duplicate {
		plh.logger.Error("Validation failed", slog.String("error", "link is duplicate"))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "link is duplicate",
			"error":   "cant use this link, it's duplicate",
		})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "link it's available",
	})
}

func (plh *publicLinkHandler) OpenFile(ctx *fiber.Ctx) error {
	link := ctx.Query("public-link")
	file := ctx.Query("file")

	plh.logger.Info("Listing public object with link", slog.String("link", link))

	res, err := plh.publicLinkService.GetRootByLink(link)

	if res.Privacy == "PRIVATE" {
		key := ctx.Query("access-key")
		if key == "" {
			return Render(ctx, error_handling.InvalidKeyAccesing(models.Alert{Type: "warning", Message: "access key empty"}))
		}
		if res.AccessKey != key {
			return Render(ctx, error_handling.InvalidKeyAccesing(models.Alert{Type: "error", Message: "access key not valid"}))
		}
	}
	if err != nil {
		plh.logger.Error("Failed to get link or link not available",
			slog.String("bucket", link),
			slog.String("error", err.Error()))
		return Render(ctx, error_handling.NotFound())
	}
	plh.logger.Info("downloading object", slog.String("bucket", res.RealRootBucket), slog.String("file", file))

	// checking if file exists
	fileExist := false
	files, _, err := plh.s3Service.ListPageFiles(ctx.Context(), res.RealRootBucket, res.RealRootPath+"/")
	if err != nil {
		plh.logger.Error("Failed to get file", slog.String("bucket", res.RealRootBucket), slog.String("file", file), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to get file")
	}
	// check every files
	for _, v := range files {
		if v == file {
			fileExist = true
		}
	}
	if !fileExist {
		plh.logger.Error("file not found", slog.String("bucket", res.RealRootBucket), slog.String("file", file))
		return ctx.Status(fiber.StatusInternalServerError).SendString("file not found")
	}

	plh.logger.Info("Opening object", slog.String("bucket", res.RealRootBucket), slog.String("file", file))

	presignedUrl, err := plh.s3Service.GetDownloadObject(ctx.Context(), res.RealRootBucket, file)
	if err != nil {
		plh.logger.Error("Failed to get presigned URL", slog.String("bucket", res.RealRootBucket), slog.String("file", file), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to get presigned URL")
	}

	return ctx.JSON(fiber.Map{
		"url": presignedUrl,
	})
}

func (plh *publicLinkHandler) DownloadFile(ctx *fiber.Ctx) error {
	link := ctx.Query("public-link")
	file := ctx.Query("file")

	plh.logger.Info("Listing public object with link", slog.String("link", link))

	res, err := plh.publicLinkService.GetRootByLink(link)

	if res.Privacy == "PRIVATE" {
		key := ctx.Query("access-key")
		if key == "" {
			return Render(ctx, error_handling.InvalidKeyAccesing(models.Alert{Type: "warning", Message: "access key empty"}))
		}
		if res.AccessKey != key {
			return Render(ctx, error_handling.InvalidKeyAccesing(models.Alert{Type: "error", Message: "access key not valid"}))
		}
	}
	if err != nil {
		plh.logger.Error("Failed to get link or link not available",
			slog.String("bucket", link),
			slog.String("error", err.Error()))
		return Render(ctx, error_handling.NotFound())
	}
	plh.logger.Info("downloading object", slog.String("bucket", res.RealRootBucket), slog.String("file", file))

	// checking if file exists
	fileExist := false
	files, _, err := plh.s3Service.ListPageFiles(ctx.Context(), res.RealRootBucket, res.RealRootPath+"/")
	if err != nil {
		plh.logger.Error("Failed to get file", slog.String("bucket", res.RealRootBucket), slog.String("file", file), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to get file")
	}
	// check every files
	for _, v := range files {
		if v == file {
			fileExist = true
		}
	}
	if !fileExist {
		plh.logger.Error("file not found", slog.String("bucket", res.RealRootBucket), slog.String("file", file))
		return ctx.Status(fiber.StatusInternalServerError).SendString("file not found")
	}

	decodedFile, err := url.QueryUnescape(file)
	if err != nil {
		plh.logger.Error("Invalid file parameter", slog.String("file", file), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).SendString("Invalid file parameter")
	}

	plh.logger.Info("Downloading object", slog.String("bucket", res.RealRootBucket), slog.String("file", decodedFile))

	presignedUrl, err := plh.s3Service.GetDownloadObject(ctx.Context(), res.RealRootBucket, decodedFile)
	if err != nil {
		plh.logger.Error("Failed to generate presigned URL", slog.String("bucket", res.RealRootBucket), slog.String("file", decodedFile), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to generate presigned URL")
	}

	plh.logger.Info("Presigned URL generated", slog.String("url", presignedUrl))

	resp, err := http.Get(presignedUrl)
	if err != nil {
		plh.logger.Error("Failed to download file", slog.String("url", presignedUrl), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to download file")
	}
	defer resp.Body.Close()

	// Set Content-Type from the response header
	contentType := resp.Header.Get("Content-Type")
	ctx.Set("Content-Type", contentType)

	if isViewableFile(contentType) {
		ctx.Set("Content-Disposition", "inline; filename="+decodedFile) // Open in new tab
	} else {
		ctx.Set("Content-Disposition", "attachment; filename="+decodedFile) // Force download
	}

	_, err = io.Copy(ctx.Response().BodyWriter(), resp.Body)
	if err != nil {
		plh.logger.Error("Failed to serve file content", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to serve file content")
	}
	return nil
}
