package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

// NewValidator initializes the validator with custom rules
func NewAuthValidator() *validator.Validate {
	validate := validator.New()
	
	// Register custom password validation rule
	validate.RegisterValidation("password", passwordValidation)

	// Additional custom validations can be added here if needed
	return validate
}

// passwordValidation checks if a password contains at least one lowercase letter,
// one uppercase letter, one number, and has a minimum length of 8 characters.
func passwordValidation(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	matched, _ := regexp.MatchString(`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$`, password)
	return matched
}
