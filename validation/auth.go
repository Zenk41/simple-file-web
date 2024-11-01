package validation

import (
	"unicode"

	"github.com/go-playground/validator/v10"
)

// NewAuthValidator initializes the validator with custom rules
func NewAuthValidator() *validator.Validate {
	validate := validator.New()
	
	// Register custom password validation rule
	validate.RegisterValidation("password", passwordValidation)

	return validate
}

// passwordValidation checks if a password contains at least one lowercase letter,
// one uppercase letter, one number, and has a minimum length of 8 characters.
func passwordValidation(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	
	// Check minimum length
	if len(password) < 8 {
		return false
	}
	
	// Flags to track password requirements
	hasLower := false
	hasUpper := false
	hasDigit := false
	
	// Iterate through characters to check requirements
	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsDigit(char):
			hasDigit = true
		}
	}
	
	// Ensure all requirements are met
	return hasLower && hasUpper && hasDigit
}