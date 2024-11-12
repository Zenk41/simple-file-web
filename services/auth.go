package services

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log/slog"
	"os"
	"time"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/google/uuid"
)

type AuthService interface {
	ReadUser() (models.User, error)
	CreateUser(payload models.RegisterPayload) error
	UpdateUser(payload models.User) error
	ReadUserWithId(id string) (models.User, error)
	UpdateOTP(user models.User) error
	EnablingOTP(user models.User) error
}

type authService struct {
	auth     models.Auth
	logger   *slog.Logger
	filename string
}

func NewAuthService(logger *slog.Logger, filename string) AuthService {

	as := &authService{
		auth:     models.Auth{},
		logger:   logger,
		filename: filename,
	}
	err := as.LoadFromFile()
	if err != nil {
		logger.Warn("Failed to load data from file", slog.String("error", err.Error()))
	}
	return as
}

func (as *authService) ReadUser() (models.User, error) {
	if as.auth.User.ID == uuid.Nil {
		as.logger.Error("user empty")
		return as.auth.User, fmt.Errorf("user is empty")
	}
	as.logger.Info("succes read user")
	return as.auth.User, nil
}

func (as *authService) CreateUser(payload models.RegisterPayload) error {
	if as.auth.User.ID != uuid.Nil {
		as.logger.Error("cannot create new user",
			slog.String("user exist with id", as.auth.User.ID.String()))
		return fmt.Errorf("user exist cant add more user")
	}

	user := models.User{}
	if err := user.EncryptPassword(payload.Password); err != nil {
		as.logger.Error("failed to encrypt password", slog.String("message", err.Error()))
		return fmt.Errorf("failed to encrypt password : %v ", err)
	}
	user.ID = uuid.New()
	user.CreatedAt = time.Now()

	user.Email = payload.Email
	user.EncryptPassword(payload.Password)
	user.Username = payload.Username

	as.auth.User = user
	as.logger.Info("created new user",
		slog.String("id", user.ID.String()),
		slog.String("username", payload.Username),
		slog.String("email", payload.Email))
	return as.SaveToFile()
}

func (as *authService) UpdateUser(payload models.User) error {
	_, err := as.ReadUser()
	if err != nil {
		as.logger.Error("cannot update user since the user is empty")
		return fmt.Errorf("cannot update user since the user is empty")
	}
	as.auth.User.Username = payload.Username
	as.auth.User.Email = payload.Email
	as.auth.User.UpdatedAt = time.Now()
	as.auth.User.OtpEnabled = payload.OtpEnabled
	as.logger.Info("user updated",
		slog.String("id", as.auth.User.ID.String()),
		slog.String("username", as.auth.User.Username),
		slog.String("email", as.auth.User.Email))
	return as.SaveToFile()
}

func (as *authService) SaveToFile() error {
	data, err := json.MarshalIndent(as.auth.User, "", "  ")
	if err != nil {
		as.logger.Error("Failed to marshal public links", slog.String("error", err.Error()))
		return err
	}

	err = ioutil.WriteFile(as.filename, data, 0644)
	if err != nil {
		as.logger.Error("Failed to write public links to file", slog.String("error", err.Error()))
		return err
	}

	as.logger.Info("Saved public links to file", slog.String("filename", as.filename))
	return nil
}

func (as *authService) LoadFromFile() error {
	_, err := os.Stat(as.filename)
	if os.IsNotExist(err) {
		as.logger.Info("Database file does not exist, creating a new one", slog.String("filename", as.filename))
		return as.SaveToFile()
	}

	data, err := ioutil.ReadFile(as.filename)
	if err != nil {
		as.logger.Error("Failed to read public links from file", slog.String("error", err.Error()))
		return err
	}

	err = json.Unmarshal(data, &as.auth.User)
	if err != nil {
		as.logger.Error("Failed to unmarshal public links", slog.String("error", err.Error()))
		return err
	}

	as.logger.Info("Loaded public links from file", slog.String("filename", as.filename), slog.String("user : ", as.auth.User.Username))
	return nil
}

func (as *authService) ReadUserWithId(id string) (models.User, error) {
	if as.auth.User.ID == uuid.Nil {
		as.logger.Error("user empty")
		return as.auth.User, fmt.Errorf("user is empty")
	}
	userId, err := uuid.Parse(id)
	if err != nil {
		as.logger.Error("cannot parse uuid")
		return as.auth.User, fmt.Errorf("uuid is not valid")
	}
	if as.auth.User.ID == userId {
		as.logger.Info("succes read user")
		return as.auth.User, nil
	}
	as.logger.Info("succes read user")
	return as.auth.User, nil
}

func (as *authService) UpdateOTP(user models.User) error {
	if user.OtpSecret == "" || user.OtpAuthUrl == "" {
		as.logger.Error("cannot update otp is empty")
		return fmt.Errorf("cannot update otp is empty")
	}
	as.auth.OtpSecret = user.OtpSecret
	as.auth.OtpAuthUrl = user.OtpAuthUrl
	return as.SaveToFile()
}

func (as *authService) EnablingOTP(user models.User) error {
	if !user.OtpEnabled || !user.OtpVerified {
		as.logger.Error("cannot enable otp is empty")
		return fmt.Errorf("cannot enable otp is empty")
	}
	as.auth.OtpEnabled = true
	as.auth.OtpVerified = true
	return as.SaveToFile()
}
