package services

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/Zenk41/simple-file-web/utils"
)

type S3Service interface {
	IsS3ConfigEmpty() bool
	InputS3Config(cfg models.ConfigS3) string
	ListPageFiles(ctx context.Context, bucket string, prefix string) ([]string, []string, error)
	ListBucket(ctx context.Context) ([]string, error)
	GetDownloadObject(ctx context.Context, bucket string, prefix string) (string, error)
	DownloadFilesAsZip(ctx context.Context, bucket, prefix string) (io.Reader, string, error)
	addToZip(ctx context.Context, bucket, file string, zipWriter *zip.Writer) error
	CreateFolder(ctx context.Context, bucket, content, folderPath string) error
	DeleteObject(ctx context.Context, bucket, path string) error
	RenameObject(ctx context.Context, bucket, oldPath, newPath string) error
	UploadFile(ctx context.Context, bucket, basePath string, file *multipart.FileHeader) error
	ReadConfig(ctx context.Context) models.ConfigS3
}
type s3Service struct {
	downloadExpiration time.Duration
	logger             *slog.Logger
}

func NewS3Service(downloadExp time.Duration, logger *slog.Logger) (S3Service, error) {
	return &s3Service{downloadExpiration: downloadExp, logger: logger}, nil
}

func (ss *s3Service) ListBucket(ctx context.Context) ([]string, error) {
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
		return []string{}, fmt.Errorf("failed to Load config: %w", err)
	}
	s3Utils := utils.NewS3Utils(cfg, ss.logger)
	buck, err := s3Utils.ListBuckets(ctx)
	if err != nil {
		return []string{}, fmt.Errorf("failed to List: %w", err)
	}

	return buck, nil
}

func (ss *s3Service) UploadFile(ctx context.Context, bucket, basePath string, file *multipart.FileHeader) error {
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
	}
	s3Utils := utils.NewS3Utils(cfg, ss.logger)

	ss.logger.Info("Starting file upload", "bucket", bucket, "basePath", basePath)

	// Validate and clean path
	basePath = path.Clean(basePath)
	ss.logger.Debug("Cleaned base path", "basePath", basePath)

	if strings.Contains(basePath, "..") {
			ss.logger.Error("Invalid path detected: path traversal attempt")
			return fmt.Errorf("invalid base path")
	}

	// Open the file
	ss.logger.Debug("Opening file", "filename", file.Filename)
	src, err := file.Open()
	if err != nil {
			ss.logger.Error("Failed to open file", "error", err)
			return fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	// Get filename and construct full path using `path.Join()` to ensure forward slashes
	filename := path.Base(file.Filename)
	fullPath := path.Join(basePath, filename)

	// Ensure all slashes are forward slashes
	fullPath = strings.ReplaceAll(fullPath, "\\", "/")
	ss.logger.Debug("Prepared file path", "filename", filename, "fullPath", fullPath)

	// Get the content type using the provided function
	contentType, err := getFileContentType(file.Filename)
	if err != nil {
			ss.logger.Error("Failed to determine content type", "error", err)
			return fmt.Errorf("failed to determine content type: %w", err)
	}

	// Use the utility to upload the file
	err = s3Utils.UploadObject(ctx, bucket, fullPath, src, contentType)
	if err != nil {
			ss.logger.Error("Failed to upload object", "error", err)
			return fmt.Errorf("failed to upload object: %w", err)
	}

	ss.logger.Info("File uploaded successfully")
	return nil
}


func (ss *s3Service) InputS3Config(cfg models.ConfigS3) string {
	if cfg.IsEmpty() {
		ss.logger.Warn("Incomplete S3 configuration provided")
		return "fail"
	}

	S3Data.FillConfig(cfg)
	ss.logger.Info("S3 configuration updated", "config", cfg)
	return "success"
}

func (ss *s3Service) IsS3ConfigEmpty() bool {
	isEmpty := S3Data.S3AccessKey == "" || S3Data.S3SecretKey == "" ||
		S3Data.S3Region == "" || S3Data.S3URL == ""
	if isEmpty {
		ss.logger.Warn("S3 configuration is incomplete")
	}
	return isEmpty
}

func (ss *s3Service) ListPageFiles(ctx context.Context, bucket string, prefix string) ([]string, []string, error) {
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}
	s3Utils := utils.NewS3Utils(cfg, ss.logger)

	// Use ListFilesAndFolders to get both files and folders.
	files, folders, err := s3Utils.ListFilesAndFolders(ctx, bucket, prefix)
	if err != nil {
		ss.logger.Error("Failed to list files and folders", "error", err)
		return nil, nil, fmt.Errorf("failed to list files and folders: %w", err)
	}

	return files, folders, nil
}

func (ss *s3Service) GetDownloadObject(ctx context.Context, bucket string, prefix string) (string, error) {
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
		return "", err
	}
	s3Utils := utils.NewS3Utils(cfg, ss.logger)

	url, err := s3Utils.GeneratePresignedURLForDownload(ctx, bucket, prefix, ss.downloadExpiration)
	if err != nil {
		ss.logger.Error("Failed to generate presigned URL", "error", err)
		return "", err
	}

	return url, nil
}

func (ss *s3Service) DownloadFilesAsZip(ctx context.Context, bucket, prefix string) (io.Reader, string, error) {
	ss.logger.Info("Starting ZIP creation", "bucket", bucket, "prefix", prefix)

	// Load S3 configuration
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
		ss.logger.Error("Error loading S3 config", "error", err)
		return nil, "", fmt.Errorf("failed to load config: %w", err)
	}
	s3Utils := utils.NewS3Utils(cfg, ss.logger)

	// List files and handle errors
	ss.logger.Info("Listing files", "bucket", bucket, "prefix", prefix)
	files, _, err := s3Utils.ListFilesAndFolders(ctx, bucket, prefix)
	if err != nil {
		ss.logger.Error("Error listing files from S3", "error", err)
		return nil, "", fmt.Errorf("failed to list files: %w", err)
	}

	// Check if files list is empty
	if len(files) == 0 {
		ss.logger.Warn("No files found", "bucket", bucket, "prefix", prefix)
		return nil, "", fmt.Errorf("no files found in the specified S3 bucket and prefix")
	}

	// Log the files found
	ss.logger.Info("Files found", "count", len(files))
	for _, file := range files {
		ss.logger.Debug("File found", "file", file)
	}

	// Use a pipe for streaming the ZIP content
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close() // Ensure the pipe is closed when done

		zipWriter := zip.NewWriter(pw)
		defer func() {
			if err := zipWriter.Close(); err != nil {
				ss.logger.Error("Failed to close zipWriter", "error", err)
				pw.CloseWithError(err)
			}
		}()

		for _, file := range files {
			ss.logger.Debug("Adding file to ZIP", "file", file)
			if err := ss.addToZip(ctx, bucket, file, zipWriter); err != nil {
				ss.logger.Error("Error adding file to zip", "file", file, "error", err)
				pw.CloseWithError(err)
				return
			}
		}
		ss.logger.Info("Successfully created ZIP file")
	}()

	return pr, fmt.Sprintf("%s.zip", prefix), nil
}

func (ss *s3Service) addToZip(ctx context.Context, bucket, file string, zipWriter *zip.Writer) error {
	ss.logger.Debug("Decoding file name", "file", file)
	decodedFile, err := url.QueryUnescape(file)
	if err != nil {
		ss.logger.Error("Failed to decode file name", "file", file, "error", err)
		return fmt.Errorf("failed to decode file name: %w", err)
	}

	ss.logger.Debug("Getting presigned URL", "file", decodedFile)
	presignedUrl, err := ss.GetDownloadObject(ctx, bucket, decodedFile)
	if err != nil {
		ss.logger.Error("Failed to get presigned URL", "file", decodedFile, "error", err)
		return fmt.Errorf("failed to get presigned URL: %w", err)
	}

	ss.logger.Debug("Downloading file from presigned URL", "url", presignedUrl)
	resp, err := http.Get(presignedUrl)
	if err != nil {
		ss.logger.Error("Failed to download file from presigned URL", "url", presignedUrl, "error", err)
		return fmt.Errorf("failed to download file from presigned URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		ss.logger.Error("Failed to download file", "url", presignedUrl, "statusCode", resp.StatusCode)
		return fmt.Errorf("failed to download file, status code: %d", resp.StatusCode)
	}

	fileName := strings.TrimPrefix(decodedFile, bucket+"/")
	ss.logger.Debug("Creating ZIP entry", "file", fileName)
	zipFile, err := zipWriter.Create(fileName)
	if err != nil {
		ss.logger.Error("Failed to create zip entry", "file", fileName, "error", err)
		return fmt.Errorf("failed to create zip entry: %w", err)
	}

	ss.logger.Debug("Copying content into ZIP", "file", fileName)
	if _, err = io.Copy(zipFile, resp.Body); err != nil {
		ss.logger.Error("Failed to copy file into ZIP", "file", fileName, "error", err)
		return fmt.Errorf("failed to copy file to zip: %w", err)
	}

	ss.logger.Debug("Successfully added file to ZIP", "file", fileName)
	return nil
}

func (ss *s3Service) CreateFolder(ctx context.Context, bucket, content, folderPath string) error {
	// Load S3 configuration
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
		ss.logger.Error("Error loading S3 config", "error", err)
		return fmt.Errorf("failed to load config: %w", err)
	}
	s3Utils := utils.NewS3Utils(cfg, ss.logger)

	// Check if the folder already exists
	existingFolders, err := s3Utils.ListFolders(ctx, bucket, folderPath)
	if err != nil {
		ss.logger.Error("Failed to list existing folders", "error", err)
		return fmt.Errorf("failed to list existing folders: %w", err)
	}

	for _, folder := range existingFolders {
		if folder == folderPath {
			ss.logger.Warn("Folder already exists", "bucket", bucket, "folder", folderPath)
			return fmt.Errorf("folder '%s' already exists in bucket '%s'", folderPath, bucket)
		}
	}

	// Create the folder
	if err := s3Utils.CreateFolder(ctx, bucket, folderPath); err != nil {
		ss.logger.Error("Failed to create folder", "bucket", bucket, "folder", folderPath, "error", err)
		return fmt.Errorf("failed to create folder '%s' in bucket '%s': %w", folderPath, bucket, err)
	}

	if err := s3Utils.PutObjectTXTWithContent(ctx, bucket, folderPath, content); err != nil {
		ss.logger.Error("Failed to put description into txt file", "bucket", bucket, "folder", folderPath, "error", err)
		return fmt.Errorf("failed to put description into txt files in folders '%s' in bucket '%s': %w", folderPath, bucket, err)
	}

	ss.logger.Info("Folder created successfully", "bucket", bucket, "folder", folderPath)
	return nil
}

func (ss *s3Service) DeleteObject(ctx context.Context, bucket, path string) error {
	ss.logger.Info("Starting to delete object", "bucket", bucket, "path", path)

	// Load the S3 configuration
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
		ss.logger.Error("Error loading S3 config", "error", err)
		return fmt.Errorf("failed to load config: %w", err)
	}
	ss.logger.Debug("Successfully loaded S3 configuration")

	// Create a new S3 Utils instance
	s3Utils := utils.NewS3Utils(cfg, ss.logger)
	ss.logger.Debug("Initialized S3 Utils instance")

	// Check if the path represents a file or a folder
	if isFolder(path) {
		// If it's a folder, attempt to delete it
		ss.logger.Info("Attempting to delete folder", "bucket", bucket, "path", path)
		if err := s3Utils.DeleteFolder(ctx, bucket, path); err != nil {
			ss.logger.Error("Error deleting folder", "error", err)
			return fmt.Errorf("failed to delete folder: %w", err)
		}
		ss.logger.Info("Folder deleted successfully", "bucket", bucket, "path", path)
	} else {
		// If it's a file, attempt to delete it
		ss.logger.Info("Attempting to delete file", "bucket", bucket, "path", path)
		if err := s3Utils.DeleteFile(ctx, bucket, path); err != nil {
			ss.logger.Error("Error deleting file", "error", err)
			return fmt.Errorf("failed to delete file: %w", err)
		}
		ss.logger.Info("File deleted successfully", "bucket", bucket, "path", path)
	}

	return nil
}

// Helper function to determine if the path represents a folder
func isFolder(path string) bool {
	// Assuming that a folder path ends with a "/"
	return strings.HasSuffix(path, "/")
}

func (ss *s3Service) RenameObject(ctx context.Context, bucket, oldPath, newPath string) error {
	ss.logger.Info("Starting to rename object", "bucket", bucket, "oldPath", oldPath, "newPath", newPath)

	// Load the S3 configuration
	cfg, err := LoadS3Config(S3Data)
	if err != nil {
		ss.logger.Error("Error loading S3 config", slog.String("error", err.Error()))
		return fmt.Errorf("failed to load config: %w", err)
	}

	s3Utils := utils.NewS3Utils(cfg, ss.logger)

	// Normalize paths by trimming extra slashes and ensuring proper endings
	oldPath = normalizePath(oldPath)
	newPath = normalizePath(newPath)

	// Check if the path represents a folder
	if isFolder(oldPath) {
		ss.logger.Info("Renaming folder", "oldPath", oldPath)

		// List all files and subfolders recursively
		allFiles, _, err := s3Utils.ListFilesAndFoldersRecursively(ctx, bucket, oldPath)
		if err != nil {
			ss.logger.Error("Failed to list files in folder", slog.String("oldPath", oldPath), slog.String("error", err.Error()))
			return fmt.Errorf("failed to list files in folder: %w", err)
		}
		ss.logger.Info("Files found in folder", "oldPath", oldPath, "files", allFiles)

		// Create new folder first
		if err := s3Utils.CreateFolder(ctx, bucket, newPath); err != nil {
			ss.logger.Error("Failed to create new folder", slog.String("newPath", newPath), slog.String("error", err.Error()))
			return fmt.Errorf("failed to create new folder: %w", err)
		}
		ss.logger.Info("Created new folder", "newPath", newPath)

		// Copy each file to the new location
		for _, file := range allFiles {
			// Calculate relative path while handling slashes properly
			relativePath := strings.TrimPrefix(file, oldPath)
			relativePath = strings.TrimPrefix(relativePath, "/")

			// Construct new path ensuring no double slashes
			newFilePath := path.Join(newPath, relativePath)

			// If the original was a folder (ended with /), ensure the new path does too
			if strings.HasSuffix(file, "/") && !strings.HasSuffix(newFilePath, "/") {
				newFilePath += "/"
			}

			ss.logger.Info("Copying file", "from", file, "to", newFilePath)

			if strings.HasSuffix(file, "/") {
				// Create subfolder
				if err := s3Utils.CreateFolder(ctx, bucket, newFilePath); err != nil {
					ss.logger.Error("Failed to create subfolder", slog.String("newFilePath", newFilePath), slog.String("error", err.Error()))
					return fmt.Errorf("failed to create subfolder %s: %w", newFilePath, err)
				}
			} else {
				// Copy the object
				if err := s3Utils.CopyObject(ctx, bucket, file, bucket, newFilePath); err != nil {
					ss.logger.Error("Failed to copy object", slog.String("from", file), slog.String("to", newFilePath), slog.String("error", err.Error()))
					return fmt.Errorf("failed to copy object %s to %s: %w", file, newFilePath, err)
				}

				// Delete the old object only after successful copy
				if err := s3Utils.DeleteFile(ctx, bucket, file); err != nil {
					ss.logger.Error("Failed to delete old object", slog.String("file", file), slog.String("error", err.Error()))
					return fmt.Errorf("failed to delete old object %s: %w", file, err)
				}
			}

			ss.logger.Info("Successfully processed file", "from", file, "to", newFilePath)
		}

		// Delete the old folder structure
		if err := s3Utils.DeleteFolderRecursively(ctx, bucket, oldPath); err != nil {
			ss.logger.Error("Failed to delete old folder structure", slog.String("oldPath", oldPath), slog.String("error", err.Error()))
			return fmt.Errorf("failed to delete old folder structure: %w", err)
		}
		ss.logger.Info("Deleted old folder structure", "oldPath", oldPath)

	} else {
		ss.logger.Info("Renaming single file", "oldPath", oldPath)

		// For single file, ensure the target directory exists
		targetDir := path.Dir(newPath)
		if targetDir != "." && targetDir != "/" {
			// Ensure the target directory path is normalized
			targetDir = normalizePath(targetDir)
			if err := s3Utils.CreateFolder(ctx, bucket, targetDir); err != nil {
				ss.logger.Error("Failed to create target directory", slog.String("targetDir", targetDir), slog.String("error", err.Error()))
				return fmt.Errorf("failed to create target directory: %w", err)
			}
		}

		// Copy and delete the file
		if err := s3Utils.CopyObject(ctx, bucket, oldPath, bucket, newPath); err != nil {
			ss.logger.Error("Failed to copy file", slog.String("from", oldPath), slog.String("to", newPath), slog.String("error", err.Error()))
			return fmt.Errorf("failed to copy file: %w", err)
		}
		ss.logger.Info("Copied file", "from", oldPath, "to", newPath)

		if err := s3Utils.DeleteFile(ctx, bucket, oldPath); err != nil {
			ss.logger.Error("Failed to delete old file", slog.String("oldPath", oldPath), slog.String("error", err.Error()))
			return fmt.Errorf("failed to delete old file: %w", err)
		}
		ss.logger.Info("Deleted old file", "oldPath", oldPath)
	}

	ss.logger.Info("Successfully renamed object", "from", oldPath, "to", newPath, "bucket", bucket)
	return nil
}

// Helper function to normalize paths
func normalizePath(p string) string {
	// Trim any leading or trailing spaces
	p = strings.TrimSpace(p)

	// Replace any multiple consecutive slashes with a single slash
	p = strings.ReplaceAll(p, "//", "/")

	// If it's a folder (ends with slash), ensure exactly one trailing slash
	if strings.HasSuffix(p, "/") {
		p = strings.TrimRight(p, "/") + "/"
	}

	// Trim any leading slash as S3 keys shouldn't start with /
	p = strings.TrimPrefix(p, "/")

	return p
}

func (ss *s3Service) ReadConfig(ctx context.Context) models.ConfigS3 {
	return S3Data
}
