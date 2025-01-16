package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type LoginPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type RegisterPayload struct {
	Username string `json:"username" validate:"required,min=4,max=10"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type RegisterOauthPayload struct {
	OauthProvider    string `json:"oauth_provider" validate:"required"`
	OauthAccessToken string `json:"oauth_access_token" validate:"required"`
	FirstName        string `json:"first_name" validate:"required"`
	LastName         string `json:"last_name" validate:"required"`
	Email            string `json:"email" validate:"required"`
}

type LoginOauthPayload struct {
	OauthProvider    string `json:"oauth_provider" validate:"required"`
	OauthAccessToken string `json:"oauth_access_token" validate:"required"`
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
	Name          string `json:"name"`
}

func (lp *LoginPayload) CheckPassword(encryptedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(lp.Password), []byte(encryptedPassword))
	if err != nil {
		return err
	}
	return nil
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username" validate:"required,min=4,max=8"`
	Email    string    `json:"email" validate:"required,email"`
	Password string    `json:"password" validate:"required,min=8"`

	OtpEnabled  bool `json:"otp_enabled"`
	OtpVerified bool `json:"otp_verified"`

	OtpSecret  string `json:"otp_secret"`
	OtpAuthUrl string `json:"otp_auth_url"`

	OauthProvider       string `json:"oauth_provider"` // Optional only if OAuth is chosen
	OauthProviderUserID string `json:"oath_provider_user_id"`

	CreatedAt time.Time
	UpdatedAt time.Time

	IsAdmin bool
}

type StateOauth struct {
	State     string
	CreatedAt time.Time
}

type OTPInput struct {
	Token string `json:"token"`
}

type Auth struct {
	User
}

func (u *User) EncryptPassword(password string) error {
	pass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(pass)
	return nil
}

func (u *User) CheckPassword(encryptedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(encryptedPassword))
	if err != nil {
		return err
	}
	return nil
}

type PasswordPayload struct {
	Password string `json:"password" validate:"required,min=8"`
}
