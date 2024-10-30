package utils

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"mime/multipart"

	"path"

	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Utils interface {
	UploadObject(ctx context.Context, bucket string, key string, file multipart.File, contentType string) error 
	GeneratePresignedURLForDownload(ctx context.Context, bucket string, key string, expiration time.Duration) (string, error)
	ListFiles(ctx context.Context, bucket string, prefix string) ([]string, error)
	DeleteFile(ctx context.Context, bucket string, key string) error
	ListFolders(ctx context.Context, bucket string, prefix string) ([]string, error)
	CreateFolder(ctx context.Context, bucket string, folderPath string) error
	ListBuckets(ctx context.Context) ([]string, error)
	ListFilesAndFolders(ctx context.Context, bucket string, prefix string) ([]string, []string, error)
	PutObjectTXTWithContent(ctx context.Context, bucket string, folderpath string, content string) error
	DeleteFolder(ctx context.Context, bucket string, folderPath string) error
	CopyObject(ctx context.Context, sourceBucket, sourcePath, destBucket, destPath string) error
	ListFilesAndFoldersRecursively(ctx context.Context, bucket string, prefix string) ([]string, []string, error)
	DeleteFolderRecursively(ctx context.Context, bucket string, folderPath string) error
}

type s3Utils struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	logger        *slog.Logger
}

func NewS3Utils(cfg aws.Config, logger *slog.Logger) S3Utils {
	client := s3.NewFromConfig(cfg)
	return &s3Utils{
		client:        client,
		presignClient: s3.NewPresignClient(client),
		logger:        logger,
	}
}

func (su *s3Utils) UploadObject(ctx context.Context, bucket string, key string, file multipart.File, contentType string) error {
	su.logger.Info("Starting S3 upload", "bucket", bucket, "key", key)

	// Clean file path to avoid path traversal
	su.logger.Debug("Cleaned file path", "key", key)
	if strings.Contains(key, "..") {
			su.logger.Error("Invalid file path detected", "key", key)
			return fmt.Errorf("invalid file path: %s", key)
	}

	// Create the PutObject input
	su.logger.Debug("Creating S3 PutObjectInput")
	input := &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Body:   file,
			ContentType: aws.String(contentType),
			// Optionally set Content-Disposition if needed
			// ContentDisposition: aws.String("inline"), // or "attachment" based on your needs
	}

	// Upload the file
	su.logger.Info("Uploading file to S3", "bucket", bucket, "key", key)
	_, err := su.client.PutObject(ctx, input)
	if err != nil {
			su.logger.Error("Failed to upload file to S3", "error", err)
			return fmt.Errorf("failed to upload file: %w", err)
	}

	su.logger.Info("File uploaded successfully to S3")
	return nil
}

func (su *s3Utils) GeneratePresignedURLForDownload(ctx context.Context, bucket string, key string, expiration time.Duration) (string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	presignedReq, err := su.presignClient.PresignGetObject(ctx, input, s3.WithPresignExpires(expiration))
	if err != nil {
		return "", err
	}

	return presignedReq.URL, nil
}

func (su *s3Utils) ListFiles(ctx context.Context, bucket string, prefix string) ([]string, error) {
	var files []string
	paginator := s3.NewListObjectsV2Paginator(su.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			files = append(files, *obj.Key)
		}
	}

	su.logger.Debug("Files found", "prefix", prefix, "files", files)

	return files, nil
}
func (su *s3Utils) DeleteFile(ctx context.Context, bucket string, key string) error {
	su.logger.Info("Starting to delete file(s)", "bucket", bucket, "key", key)
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(key), // Key represents the folder path
	}

	var objectsToDelete []types.ObjectIdentifier

	paginator := s3.NewListObjectsV2Paginator(su.client, input)
	for paginator.HasMorePages() {
		su.logger.Debug("Fetching next page of objects")
		page, err := paginator.NextPage(ctx)
		if err != nil {
			su.logger.Error("Failed to list objects", "error", err)
			return fmt.Errorf("failed to list objects: %w", err)
		}

		su.logger.Debug("Found objects in the page", "count", len(page.Contents))
		for _, obj := range page.Contents {
			su.logger.Debug("Adding object to delete", "key", *obj.Key)
			objectsToDelete = append(objectsToDelete, types.ObjectIdentifier{
				Key: obj.Key,
			})
		}
	}

	// Delete objects found
	if len(objectsToDelete) > 0 {
		su.logger.Info("Deleting objects", "count", len(objectsToDelete))
		_, err := su.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &types.Delete{
				Objects: objectsToDelete,
			},
		})
		if err != nil {
			su.logger.Error("Failed to delete objects", "error", err)
			return fmt.Errorf("failed to delete objects: %w", err)
		}
		su.logger.Info("Successfully deleted objects")
	} else {
		su.logger.Info("No objects to delete")
	}

	return nil
}

func (su *s3Utils) DeleteFolder(ctx context.Context, bucket string, folderPath string) error {
	// Ensure folderPath ends with a slash
	if !strings.HasSuffix(folderPath, "/") {
		folderPath += "/"
	}
	fmt.Printf("Starting to delete folder: %s in bucket: %s\n", folderPath, bucket)

	// Prepare to list objects with the given prefix (folder path)
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(folderPath),
	}

	var objectsToDelete []types.ObjectIdentifier

	// Use paginator to list objects under the folder
	paginator := s3.NewListObjectsV2Paginator(su.client, input)
	for paginator.HasMorePages() {
		fmt.Println("Fetching next page of folder objects...")
		page, err := paginator.NextPage(ctx)
		if err != nil {
			fmt.Printf("Failed to list objects in folder: %v\n", err)
			return fmt.Errorf("failed to list objects in folder: %w", err)
		}

		fmt.Printf("Found %d objects in the folder page\n", len(page.Contents))
		// Collect objects to delete
		for _, obj := range page.Contents {
			fmt.Printf("Adding folder object to delete: %s\n", *obj.Key)
			objectsToDelete = append(objectsToDelete, types.ObjectIdentifier{
				Key: obj.Key,
			})
		}
	}

	// Delete the objects under the folder if found
	if len(objectsToDelete) > 0 {
		fmt.Printf("Deleting %d folder objects...\n", len(objectsToDelete))
		_, err := su.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &types.Delete{
				Objects: objectsToDelete,
			},
		})
		if err != nil {
			fmt.Printf("Failed to delete folder objects: %v\n", err)
			return fmt.Errorf("failed to delete folder objects: %w", err)
		}
		fmt.Println("Successfully deleted folder objects.")
	} else {
		fmt.Println("No objects found in the folder to delete.")
	}

	return nil
}

func (su *s3Utils) ListFolders(ctx context.Context, bucket string, prefix string) ([]string, error) {
	folderMap := make(map[string]struct{})
	paginator := s3.NewListObjectsV2Paginator(su.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, obj := range page.Contents {
			if key := *obj.Key; key != prefix {
				if idx := strings.Index(key[len(prefix):], "/"); idx != -1 {
					folder := key[:len(prefix)+idx+1]
					folderMap[folder] = struct{}{}
				}
			}
		}
	}

	// Convert map keys to slice
	folders := make([]string, 0, len(folderMap))
	for folder := range folderMap {
		folders = append(folders, folder)
	}

	return folders, nil
}

// CreateFolder creates a new folder in the specified S3 bucket, allowing for nested folders.
func (su *s3Utils) CreateFolder(ctx context.Context, bucket string, folderPath string) error {
	input := &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(folderPath + "/"), // Append slash to indicate a folder
	}
	_, err := su.client.PutObject(ctx, input)
	return err
}

func (su *s3Utils) PutObjectTXTWithContent(ctx context.Context, bucket string, folderpath string, content string) error {
	buffer := bytes.NewBufferString(content)
	_, err := su.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(folderpath + "/info.txt"),
		Body:        buffer,
		ContentType: aws.String("text/plain"), // Set the content type
	})
	return err
}

func (su *s3Utils) ListBuckets(ctx context.Context) ([]string, error) {
	var bucketNames []string
	output, err := su.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	// Iterate over the bucket names and add them to the slice
	for _, bucket := range output.Buckets {
		bucketNames = append(bucketNames, *bucket.Name)
	}

	su.logger.Debug("Available buckets", "buckets", bucketNames)

	return bucketNames, nil
}

func (su *s3Utils) ListFilesAndFolders(ctx context.Context, bucket string, prefix string) ([]string, []string, error) {
	var files []string
	var folders []string

	paginator := s3.NewListObjectsV2Paginator(su.client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}

		// Add files
		for _, obj := range page.Contents {
			if !strings.HasSuffix(*obj.Key, "/") { // Identify files without trailing slash
				files = append(files, *obj.Key)
			}
		}

		// Add folders
		for _, cp := range page.CommonPrefixes {
			if *cp.Prefix != prefix { // Ensure the folder isn't the same as the prefix
				folders = append(folders, *cp.Prefix)
			}
		}
	}

	// Debugging output
	fmt.Printf("Files: %v\nFolders: %v\n", files, folders)

	return files, folders, nil
}

func (s *s3Utils) CopyObject(ctx context.Context, sourceBucket, sourcePath, destBucket, destPath string) error {
	source := fmt.Sprintf("%s/%s", sourceBucket, sourcePath)
	input := &s3.CopyObjectInput{
		Bucket:     aws.String(destBucket),
		CopySource: aws.String(source),
		Key:        aws.String(destPath),
	}

	_, err := s.client.CopyObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to copy object: %w", err)
	}

	return nil
}

// ListFilesAndFoldersRecursively lists all files and folders recursively under the specified prefix
func (su *s3Utils) ListFilesAndFoldersRecursively(ctx context.Context, bucket string, prefix string) ([]string, []string, error) {
	var files []string
	var folders []string
	folderMap := make(map[string]struct{}) // To keep track of unique folders

	// Ensure prefix ends with slash if it's not empty
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	paginator := s3.NewListObjectsV2Paginator(su.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			key := *obj.Key

			// Skip the prefix itself
			if key == prefix {
				continue
			}

			if strings.HasSuffix(key, "/") {
				// This is a folder
				folders = append(folders, key)

				// Add all parent folders to the folderMap
				parts := strings.Split(strings.TrimSuffix(key, "/"), "/")
				currentPath := ""
				for i := 0; i < len(parts); i++ {
					if i > 0 {
						currentPath += "/"
					}
					currentPath += parts[i]
					if currentPath+"/" != prefix { // Don't include the prefix itself
						folderMap[currentPath+"/"] = struct{}{}
					}
				}
			} else {
				// This is a file
				files = append(files, key)

				// Add all parent folders to the folderMap
				dir := path.Dir(key)
				if dir != "." {
					parts := strings.Split(dir, "/")
					currentPath := ""
					for i := 0; i < len(parts); i++ {
						if i > 0 {
							currentPath += "/"
						}
						currentPath += parts[i]
						if currentPath+"/" != prefix { // Don't include the prefix itself
							folderMap[currentPath+"/"] = struct{}{}
						}
					}
				}
			}
		}
	}

	// Convert folderMap to folders slice
	folders = make([]string, 0, len(folderMap))
	for folder := range folderMap {
		folders = append(folders, folder)
	}

	fmt.Printf("Recursively found files: %v\nFolders: %v\n", files, folders)
	return files, folders, nil
}

// DeleteFolderRecursively deletes a folder and all its contents recursively
func (su *s3Utils) DeleteFolderRecursively(ctx context.Context, bucket string, folderPath string) error {
	// Ensure folderPath ends with a slash
	if !strings.HasSuffix(folderPath, "/") {
		folderPath += "/"
	}

	su.logger.Info("Starting recursive deletion of folder", "bucket", bucket, "folderPath", folderPath)

	const maxRetries = 3
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		// List all objects in the folder
		paginator := s3.NewListObjectsV2Paginator(su.client, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
			Prefix: aws.String(folderPath),
		})

		var objectsToDelete []types.ObjectIdentifier
		foundObjects := false

		// Collect all objects to delete
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("failed to list objects in folder: %w", err)
			}

			for _, obj := range page.Contents {
				foundObjects = true
				objectsToDelete = append(objectsToDelete, types.ObjectIdentifier{
					Key: obj.Key,
				})

				// AWS limits DeleteObjects to 1000 objects per request
				if len(objectsToDelete) == 1000 {
					if err := su.deleteObjectBatch(ctx, bucket, objectsToDelete); err != nil {
						lastErr = err
						continue
					}
					objectsToDelete = nil
				}
			}
		}

		// Delete any remaining objects
		if len(objectsToDelete) > 0 {
			if err := su.deleteObjectBatch(ctx, bucket, objectsToDelete); err != nil {
				lastErr = err
				continue
			}
		}

		// If we didn't find any objects and there were no errors, we're done
		if !foundObjects && lastErr == nil {
			su.logger.Info("Successfully deleted folder", "folderPath", folderPath)
			return nil
		}

		// If we had an error, wait before retrying
		if lastErr != nil && retry < maxRetries-1 {
			su.logger.Warn("Retrying folder deletion", "retry", retry+1, "error", lastErr)
			time.Sleep(time.Duration(retry+1) * time.Second)
		}
	}

	if lastErr != nil {
		su.logger.Error("Failed to delete folder after retries", "maxRetries", maxRetries, "error", lastErr)
		return fmt.Errorf("failed to delete folder after %d retries: %w", maxRetries, lastErr)
	}

	return nil
}

// Helper function to delete a batch of objects
func (su *s3Utils) deleteObjectBatch(ctx context.Context, bucket string, objects []types.ObjectIdentifier) error {
	if len(objects) == 0 {
		return nil
	}

	su.logger.Info("Deleting batch of objects", "count", len(objects))
	_, err := su.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{
			Objects: objects,
		},
	})
	if err != nil {
		su.logger.Error("Failed to delete objects batch", "error", err)
		return fmt.Errorf("failed to delete objects batch: %w", err)
	}

	return nil
}