package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

// NewS3Validator creates a validator with S3-related custom validations
func NewS3Validator() *validator.Validate {
	validate := validator.New()

	// Register custom validations
	validate.RegisterValidation("s3region", garageRegionValidator)
	validate.RegisterValidation("s3url", s3URLValidator)
	validate.RegisterValidation("s3secretkey", s3SecretKeyValidator)
	validate.RegisterValidation("s3accesskey", s3AccessKeyValidator)

	return validate
}

// garageRegionValidator validates S3 region format
func garageRegionValidator(fl validator.FieldLevel) bool {
	s3region := fl.Field().String()
	matched, _ := regexp.MatchString(`^(garage|[a-z]{2}-[a-z]+-\d)$`, s3region)
	return matched
}

// s3URLValidator validates S3 URL format
func s3URLValidator(fl validator.FieldLevel) bool {
	s3url := fl.Field().String()
	matched, _ := regexp.MatchString(`^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s]*)?$`, s3url)
	return matched
}

// s3SecretKeyValidator validates S3 secret key format
func s3SecretKeyValidator(fl validator.FieldLevel) bool {
	secretKey := fl.Field().String()
	matched, _ := regexp.MatchString(`^[A-Za-z0-9/+=]+$`, secretKey)
	return matched
}

// s3AccessKeyValidator validates S3 access key format
func s3AccessKeyValidator(fl validator.FieldLevel) bool {
	accessKey := fl.Field().String()
	matched, _ := regexp.MatchString(`^[A-Za-z0-9]{16,40}$`, accessKey)
	return matched
}
