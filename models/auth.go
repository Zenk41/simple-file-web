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
	Username string `json:"username" validate:"required,min=4,max=8"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
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
	
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type OTPInput struct {
	Token  string `json:"token"`
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
