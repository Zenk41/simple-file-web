package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

func NewPublicLinkValidator() *validator.Validate {
	validate := validator.New()

	validate.RegisterValidation("link", linkValidator)
	validate.RegisterValidation("bucket", bucketValidator)
	
	return validate
}

func linkValidator(fl validator.FieldLevel) bool {
	link := fl.Field().String()
	matched, _ := regexp.MatchString(`^[a-z_-]+$`, link)
	return matched
}

func bucketValidator(fl validator.FieldLevel) bool {
	bucket := fl.Field().String()
	if len(bucket) < 3 || len(bucket) > 63 {
		return false
	}

	// Bucket name must not contain uppercase letters
	if bucket != string([]byte(bucket)) {
		return false
	}

	// Bucket name must start and end with a lowercase letter or number
	if !regexp.MustCompile(`^[a-z0-9].*[a-z0-9]$`).MatchString(bucket) {
		return false
	}

	// Bucket name can contain only lowercase letters, numbers, hyphens, and periods
	if !regexp.MustCompile(`^[a-z0-9.-]+$`).MatchString(bucket) {
		return false
	}

	// Bucket name must not contain consecutive periods
	if regexp.MustCompile(`\.\.`).MatchString(bucket) {
		return false
	}

	// Bucket name must not be formatted as an IP address
	if regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`).MatchString(bucket) {
		return false
	}

	return true
}