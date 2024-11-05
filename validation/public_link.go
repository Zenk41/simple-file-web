package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

func NewPublicLinkValidator() *validator.Validate {
	validate := validator.New()

	validate.RegisterValidation("link", linkValidator)
	validate.RegisterValidation("bucket", bucketValidator)
	validate.RegisterValidation("path", pathValidator)
	validate.RegisterValidation("accesstype", accessTypeValidator)
	validate.RegisterValidation("accesskey", accessKeyValidator)
	validate.RegisterValidation("privacy", privacyValidator)

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

func pathValidator(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	matched, _ := regexp.MatchString(`^(\/?[a-z_-]+\/)+$`, path)
	return matched
}

func accessTypeValidator(fl validator.FieldLevel) bool {
	accessType := fl.Field().String()

	// Define regex to match exact values
	regex := `^(FULL_ACCESS|MODIFY|EDIT|VIEW_ONLY|CREATE_ONLY)$`
	matched, err := regexp.MatchString(regex, accessType)
	if err != nil {
		return false
	}

	return matched
}

func accessKeyValidator(fl validator.FieldLevel) bool {
	accessKey := fl.Field().String()
	regex := `^(\/?[a-zA-Z0-9]+\/?)+$`
	matched, err := regexp.MatchString(regex, accessKey)
	if err != nil {
		return false
	}

	return matched
}

func privacyValidator(fl validator.FieldLevel) bool {
	privacy := fl.Field().String()
	regex := `^(PUBLIC|PRIVATE)$`
	matched, err := regexp.MatchString(regex, privacy)
	if err != nil {
		return false
	}

	return matched
}
