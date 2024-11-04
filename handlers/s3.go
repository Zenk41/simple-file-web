package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/services"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type ApiHandler interface {
	PostFormKeyS3(ctx *fiber.Ctx) error
	DownloadObject(ctx *fiber.Ctx) error
	OpenObject(ctx *fiber.Ctx) error
	DownloadObjectsAsZip(ctx *fiber.Ctx) error
	CreateFolder(ctx *fiber.Ctx) error
	DeleteObject(ctx *fiber.Ctx) error
	RenameObject(ctx *fiber.Ctx) error
	UploadObject(ctx *fiber.Ctx) error
}

type apiHandler struct {
	s3Service services.S3Service
	logger    *slog.Logger
	validator *validator.Validate
}

func NewApiHandler(s3Service services.S3Service, logger *slog.Logger, validator *validator.Validate) ApiHandler {
	return &apiHandler{s3Service: s3Service, logger: logger, validator: validator}
}

func (ah *apiHandler) UploadObject(ctx *fiber.Ctx) error {
	ah.logger.Info("Starting upload handler", slog.String("Request ID", ctx.GetRespHeader("X-Request-ID", "unknown")))

	// Parse multipart form
	ah.logger.Info("Parsing multipart form")
	form, err := ctx.MultipartForm()
	if err != nil {
		ah.logger.Error("Error parsing multipart form", slog.Any("error", err))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse upload form",
		})
	}
	ah.logger.Info("Multipart form parsed successfully")

	// Get files and validate
	files := form.File["files"]
	ah.logger.Info("Number of files received", slog.Int("file_count", len(files)))
	if len(files) == 0 {
		ah.logger.Warn("No files provided in request")
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No files provided for upload",
		})
	}

	// Get and validate form parameters
	bucket := ctx.FormValue("bucket")
	path := ctx.FormValue("path", "/")
	ah.logger.Info("Received bucket and path", slog.String("bucket", bucket), slog.String("path", path))
	if bucket == "" {
		ah.logger.Warn("Bucket name is missing")
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Bucket name is required",
		})
	}

	// Upload files
	for _, file := range files {
		ah.logger.Info("Uploading file", slog.String("filename", file.Filename))
		err := ah.s3Service.UploadFile(ctx.Context(), bucket, path, file)
		if err != nil {
			ah.logger.Error("Failed to upload file", slog.String("filename", file.Filename), slog.Any("error", err))
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to upload file " + file.Filename,
			})
		}
		ah.logger.Info("Successfully uploaded file", slog.String("filename", file.Filename))
	}

	ah.logger.Info("All files uploaded successfully")
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "Files uploaded successfully",
		"redirect": "/b/" + bucket + "/" + filepath.Clean(path) + "/",
	})
}

func (ah *apiHandler) PostFormKeyS3(ctx *fiber.Ctx) error {

	payload := new(models.ConfigS3)

	if err := ctx.BodyParser(payload); err != nil {
		ah.logger.Error("Invalid request body", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request body",
			"error":   err.Error(),
		})
	}

	if err := ah.validator.Struct(payload); err != nil {
		ah.logger.Error("Validation failed", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Validation failed",
			"error":   err.Error(),
		})
	}

	str := ah.s3Service.InputS3Config(*payload)
	ah.logger.Info("PostFormKeyS3: S3 config set", slog.String("config", str))
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "success filling s3 config",
	})
}

func (ah *apiHandler) DownloadObject(ctx *fiber.Ctx) error {
	bucket := ctx.Query("bucket")
	file := ctx.Query("file")

	decodedFile, err := url.QueryUnescape(file)
	if err != nil {
		ah.logger.Error("Invalid file parameter", slog.String("file", file), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusBadRequest).SendString("Invalid file parameter")
	}

	ah.logger.Info("Downloading object", slog.String("bucket", bucket), slog.String("file", decodedFile))

	presignedUrl, err := ah.s3Service.GetDownloadObject(ctx.Context(), bucket, decodedFile)
	if err != nil {
		ah.logger.Error("Failed to generate presigned URL", slog.String("bucket", bucket), slog.String("file", decodedFile), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to generate presigned URL")
	}

	ah.logger.Info("Presigned URL generated", slog.String("url", presignedUrl))

	resp, err := http.Get(presignedUrl)
	if err != nil {
		ah.logger.Error("Failed to download file", slog.String("url", presignedUrl), slog.String("error", err.Error()))
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
		ah.logger.Error("Failed to serve file content", slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to serve file content")
	}
	return nil
}

func (ah *apiHandler) OpenObject(ctx *fiber.Ctx) error {
	bucket := ctx.Query("bucket")
	file := ctx.Query("file")

	ah.logger.Info("Opening object", slog.String("bucket", bucket), slog.String("file", file))

	presignedUrl, err := ah.s3Service.GetDownloadObject(ctx.Context(), bucket, file)
	if err != nil {
		ah.logger.Error("Failed to get presigned URL", slog.String("bucket", bucket), slog.String("file", file), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to get presigned URL")
	}

	return ctx.JSON(fiber.Map{
		"url": presignedUrl,
	})
}

func (ah *apiHandler) DownloadObjectsAsZip(ctx *fiber.Ctx) error {
	bucket := ctx.Query("bucket")
	path := ctx.Query("path")

	ah.logger.Info("Downloading objects as ZIP", slog.String("bucket", bucket), slog.String("path", path))

	zipReader, filename, err := ah.s3Service.DownloadFilesAsZip(ctx.Context(), bucket, path)
	if err != nil {
		ah.logger.Error("Failed to create ZIP file", slog.String("bucket", bucket), slog.String("path", path), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to create ZIP file")
	}

	ctx.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	ctx.Set("Content-Type", "application/zip")

	if _, err = io.Copy(ctx.Response().BodyWriter(), zipReader); err != nil {
		ah.logger.Error("Failed to stream ZIP content", slog.String("bucket", bucket), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Failed to stream ZIP content")
	}

	if closer, ok := zipReader.(io.ReadCloser); ok {
		if err := closer.Close(); err != nil {
			ah.logger.Error("Error closing zipReader", slog.String("error", err.Error()))
		}
	}

	return nil
}

func (ah *apiHandler) CreateFolder(ctx *fiber.Ctx) error {
	bucket := ctx.Query("bucket")
	paths := ctx.Query("path")
	name := ctx.FormValue("name")
	description := ctx.FormValue("description")

	if bucket == "" || name == "" {
		ah.logger.Warn("Missing required fields for folder creation", slog.String("bucket", bucket), slog.String("name", name))
		return ctx.Status(fiber.StatusBadRequest).SendString("Bucket, path, and name are required fields")
	}

	if paths == "" {
		paths = "/"
	} else if paths[len(paths)-1] != '/' {
		paths += "/"
	}

	folderPath := paths + name
	ah.logger.Info("Creating folder", slog.String("bucket", bucket), slog.String("folderPath", folderPath))

	if err := ah.s3Service.CreateFolder(ctx.Context(), bucket, description, folderPath); err != nil {
		ah.logger.Error("Error creating folder", slog.String("bucket", bucket), slog.String("folderPath", folderPath), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).SendString("Error creating folder: " + err.Error())
	}

	redirect := "/b/" + bucket + "/" + folderPath
	ah.logger.Info("Folder created successfully", slog.String("bucket", bucket), slog.String("path", folderPath))
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "Folder '" + name + "' created successfully at path: " + folderPath,
		"bucket":   bucket,
		"path":     folderPath,
		"redirect": redirect,
	})
}

func (ah *apiHandler) DeleteObject(ctx *fiber.Ctx) error {
	bucket := ctx.Query("bucket")
	paths := ctx.Query("path")

	if bucket == "" || paths == "" {
		ah.logger.Warn("Missing required fields for deletion", slog.String("bucket", bucket), slog.String("path", paths))
		return ctx.Status(fiber.StatusBadRequest).SendString("Bucket and path are required fields")
	}

	ah.logger.Info("Deleting object", slog.String("bucket", bucket), slog.String("path", paths))
	err := ah.s3Service.DeleteObject(ctx.Context(), bucket, paths)
	if err != nil {
		ah.logger.Error("Failed to delete object", slog.String("bucket", bucket), slog.String("path", paths), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to delete object at path: %s", paths),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  fmt.Sprintf("Object '%s' deleted successfully", path.Base(paths)),
		"bucket":   bucket,
		"path":     paths,
		"redirect": "/b/" + bucket + "/" + filepath.Dir(filepath.Clean(paths)) + "/",
	})
}

func (ah *apiHandler) RenameObject(ctx *fiber.Ctx) error {
	bucket := ctx.Query("bucket")
	oldPath := ctx.Query("path")
	newName := ctx.FormValue("newName")

	if bucket == "" || oldPath == "" || newName == "" {
		ah.logger.Warn("Missing required parameters for renaming", slog.String("bucket", bucket), slog.String("oldPath", oldPath), slog.String("newName", newName))
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Bucket, path, and new name are required fields",
		})
	}

	parentPath := filepath.Dir(filepath.Clean(oldPath))
	if parentPath != "/" {
		parentPath += "/"
	}

	var newPath string
	if isFolder(oldPath) {
		newPath = strings.ReplaceAll(filepath.Join(parentPath, newName), "\\", "/")
	} else {
		ext := filepath.Ext(oldPath)
		if ext != "" && filepath.Ext(newName) == "" {
			newName += ext
		}
		newPath = strings.ReplaceAll(filepath.Join(parentPath, newName), "\\", "/")
	}

	ah.logger.Info("Renaming object", slog.String("bucket", bucket), slog.String("oldPath", oldPath), slog.String("newPath", newPath))
	if err := ah.s3Service.RenameObject(ctx.Context(), bucket, oldPath, newPath); err != nil {
		ah.logger.Error("Failed to rename object", slog.String("bucket", bucket), slog.String("oldPath", oldPath), slog.String("newPath", newPath), slog.String("error", err.Error()))
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to rename object: " + err.Error(),
		})
	}

	redirectPath := "/b/" + bucket + "/" + parentPath
	ah.logger.Info("Successfully renamed object", slog.String("oldPath", oldPath), slog.String("newPath", newPath))

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  fmt.Sprintf("Successfully renamed '%s' to '%s'", path.Base(oldPath), path.Base(newPath)),
		"bucket":   bucket,
		"oldPath":  oldPath,
		"newPath":  newPath,
		"redirect": redirectPath,
	})
}

// Helper function to check if a path represents a folder
func isFolder(path string) bool {
	return strings.HasSuffix(path, "/")
}

// Function to determine if the file can be viewed in the browser
func isViewableFile(contentType string) bool {
	return strings.HasPrefix(contentType, "image/") || // All image types
		contentType == "application/pdf" || // PDF files
		contentType == "text/html" || // HTML files
		contentType == "text/plain" || // Plain text files
		contentType == "application/json" || // JSON files
		contentType == "text/css" || // CSS files
		contentType == "text/csv" || // CSV files
		contentType == "text/xml" || // XML files
		contentType == "text/markdown" || // Markdown files
		contentType == "text/javascript" || // JavaScript files
		contentType == "application/javascript" // JavaScript files (alternative)
}
