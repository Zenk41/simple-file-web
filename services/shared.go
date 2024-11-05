package services

import (
	"context"

	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

var S3Data models.ConfigS3 = models.ConfigS3{S3AccessKey: "GK758db3969aacf9d618d16600",
	S3SecretKey: "e439720e6d7377fa4be9958fbe5c88fb54dabe66bbe325aa5c9fe476c1d48d73",
	S3Region:    "garage",
	S3URL:       "https://storage.ardhidhani.dev"}



func LoadS3Config(s3Data models.ConfigS3) (aws.Config, error) {

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(s3Data.S3Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			s3Data.S3AccessKey,
			s3Data.S3SecretKey,
			"",
		)),
		config.WithEndpointResolver(aws.EndpointResolverFunc(
			func(service, region string) (aws.Endpoint, error) {

				slog.Info("Requesting service", slog.String("service", service)) // Log the requested service

				return aws.Endpoint{
					URL:               s3Data.S3URL,
					SigningRegion:     "", // Change as necessary or set to "" if not needed
					HostnameImmutable: true,
				}, nil
			},
		)),
	)

	if err != nil {
		return cfg, err
	}

	return cfg, nil
}

func getFileContentType(filename string) (string, error) {
	// First, try to detect by extension
	ext := filepath.Ext(filename)
	mimeType := mime.TypeByExtension(ext)
	if mimeType != "" {
		return mimeType, nil
	}

	// If that fails, try to detect by content
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Only the first 512 bytes are used to sniff the content type.
	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		return "", err
	}

	// Use the net/http package's handy DetectContentType function
	contentType := http.DetectContentType(buffer)

	return contentType, nil
}
