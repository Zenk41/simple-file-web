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

type Ob1 struct {
	LoginPayload LoginPayload
	IsDone       bool
}

type Ob2 struct {
	AuthKey  string
	Recovery string
	IsDone   bool
}

type Ob3 struct {
	IsDone bool
}

type OnBoarding struct {
	Ob1
	Ob2
	Ob3
}

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username" validate:"required,min=4,max=8"`
	Email        string    `json:"email" validate:"required,email"`
	Password     string    `json:"password" validate:"required,min=8"`
	RecoveryCode string    `json:"recovery_code"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Auth struct {
	User
	OnBoarding
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