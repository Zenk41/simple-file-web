package services

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Zenk41/simple-file-web/models"
	"github.com/google/uuid"
)

type AuthService interface {
	ReadUsers() ([]models.User, error)
	CreateUser(payload models.RegisterPayload) error
	UpdateUser(payload models.User) error
	ReadUserWithId(id string) (models.User, error)
	UpdateOTP(userId string, user models.User) error
	EnablingOTP(userId string, user models.User) error
	CreateAdmin(payload models.RegisterPayload) error
	ReadUserByEmail(email string) (models.User, error)
	CreateWithOauth(googleUser models.GoogleUserInfo) error
	OauthUserExists(googleUser models.GoogleUserInfo) (models.User, error)
	IsAdmin(id string) bool
}

type authService struct {
	users      []models.User
	logger     *slog.Logger
	filename   string
	oauthState []models.StateOauth
}

func NewAuthService(logger *slog.Logger, filename string) AuthService {

	as := &authService{
		users:      []models.User{},
		logger:     logger,
		filename:   filename,
		oauthState: []models.StateOauth{},
	}
	err := as.LoadFromFile()
	if err != nil {
		logger.Warn("Failed to load data from file", slog.String("error", err.Error()))
	}
	return as
}

func (as *authService) ReadUsers() ([]models.User, error) {
	if len(as.users) == 0 {
		as.logger.Error("no users found")
		return nil, fmt.Errorf("no users found")
	}
	as.logger.Info("success read users", slog.Int("count", len(as.users)))
	return as.users, nil
}

func (as *authService) isEmailDuplicate(email string) bool {
	for _, user := range as.users {
		if user.Email == email {
			return true
		}
	}
	return false
}

func (as *authService) CreateUserOauth(googleUser models.GoogleUserInfo) error {
	if as.isEmailDuplicate(googleUser.Email) {
		return fmt.Errorf("email already exists")
	}

	user := models.User{
		ID:        uuid.New(),
		Email:     googleUser.Email,
		Username:  googleUser.Name,
		CreatedAt: time.Now(),
		IsAdmin:   false,
	}

	as.users = append(as.users, user)
	return as.SaveToFile()
}

func (as *authService) CreateUser(payload models.RegisterPayload) error {
	if as.isEmailDuplicate(payload.Email) {
		return fmt.Errorf("email already exists")
	}

	user := models.User{}
	if err := user.EncryptPassword(payload.Password); err != nil {
		as.logger.Error("failed to encrypt password", slog.String("message", err.Error()))
		return fmt.Errorf("failed to encrypt password : %v ", err)
	}

	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.Email = payload.Email
	user.Username = payload.Username
	user.IsAdmin = false

	as.users = append(as.users, user)
	as.logger.Info("created new user",
		slog.String("id", user.ID.String()),
		slog.String("username", payload.Username),
		slog.String("email", payload.Email))
	return as.SaveToFile()
}

func (as *authService) UpdateUser(payload models.User) error {
	for i, user := range as.users {
		if user.ID == payload.ID {
			as.users[i].Username = payload.Username
			as.users[i].Email = payload.Email
			as.users[i].UpdatedAt = time.Now()
			as.users[i].OtpEnabled = payload.OtpEnabled

			as.logger.Info("user updated",
				slog.String("id", user.ID.String()),
				slog.String("username", user.Username),
				slog.String("email", user.Email))
			return as.SaveToFile()
		}
	}
	return fmt.Errorf("user not found")
}

func (as *authService) SaveToFile() error {
	data, err := json.MarshalIndent(as.users, "", "  ")
	if err != nil {
		as.logger.Error("Failed to marshal users", slog.String("error", err.Error()))
		return err
	}

	err = os.WriteFile(as.filename, data, 0644)
	if err != nil {
		as.logger.Error("Failed to write users to file", slog.String("error", err.Error()))
		return err
	}

	as.logger.Info("Saved users to file", slog.String("filename", as.filename))
	return nil
}

func (as *authService) LoadFromFile() error {
	_, err := os.Stat(as.filename)
	if os.IsNotExist(err) {
		as.logger.Info("Database file does not exist, creating a new one", slog.String("filename", as.filename))
		return as.SaveToFile()
	}

	data, err := os.ReadFile(as.filename)
	if err != nil {
		as.logger.Error("Failed to read users from file", slog.String("error", err.Error()))
		return err
	}

	err = json.Unmarshal(data, &as.users)
	if err != nil {
		as.logger.Error("Failed to unmarshal users", slog.String("error", err.Error()))
		return err
	}

	as.logger.Info("Loaded users from file", slog.String("filename", as.filename), slog.Int("user count", len(as.users)))
	return nil
}

func (as *authService) ReadUserWithId(id string) (models.User, error) {
	userId, err := uuid.Parse(id)
	if err != nil {
		as.logger.Error("cannot parse uuid")
		return models.User{}, fmt.Errorf("uuid is not valid")
	}

	for _, user := range as.users {
		if user.ID == userId {
			as.logger.Info("success read user")
			fmt.Println(user)
			return user, nil
		}
	}

	return models.User{}, fmt.Errorf("user not found")
}

func (as *authService) ReadUserByEmail(email string) (models.User, error) {
	for _, user := range as.users {
		if user.Email == email {
			return user, nil
		}
	}
	return models.User{}, fmt.Errorf("user not found")
}

func (as *authService) UpdateOTP(userId string, user models.User) error {
	if user.OtpSecret == "" || user.OtpAuthUrl == "" {
		as.logger.Error("cannot update otp is empty")
		return fmt.Errorf("cannot update otp is empty")
	}

	for i, existingUser := range as.users {
		if existingUser.ID.String() == userId {
			as.users[i].OtpSecret = user.OtpSecret
			as.users[i].OtpAuthUrl = user.OtpAuthUrl
			return as.SaveToFile()
		}
	}
	return fmt.Errorf("user not found")
}

func (as *authService) EnablingOTP(userId string, user models.User) error {
	if !user.OtpEnabled || !user.OtpVerified {
		as.logger.Error("cannot enable otp is empty")
		return fmt.Errorf("cannot enable otp is empty")
	}

	for i, existingUser := range as.users {
		if existingUser.ID.String() == userId {
			as.users[i].OtpEnabled = true
			as.users[i].OtpVerified = true
			return as.SaveToFile()
		}
	}
	return fmt.Errorf("user not found")
}

func (as *authService) CreateAdmin(payload models.RegisterPayload) error {
	if as.isEmailDuplicate(payload.Email) {
		return fmt.Errorf("email already exists")
	}

	user := models.User{}
	if err := user.EncryptPassword(payload.Password); err != nil {
		as.logger.Error("failed to encrypt password", slog.String("message", err.Error()))
		return fmt.Errorf("failed to encrypt password : %v ", err)
	}

	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.Email = payload.Email
	user.Username = payload.Username
	user.IsAdmin = true

	as.users = append(as.users, user)
	as.logger.Info("created new admin user",
		slog.String("id", user.ID.String()),
		slog.String("username", payload.Username),
		slog.String("email", payload.Email))
	return as.SaveToFile()
}

func (as *authService) CreateWithOauth(googleUser models.GoogleUserInfo) error {
	if !googleUser.VerifiedEmail {
		as.logger.Error("can't create user, email not verified", slog.String("message", "email not verified"))
		return fmt.Errorf("can't create user, email not verified ")
	}
	if as.isEmailDuplicate(googleUser.Email) {
		as.logger.Error("failed to create user via oauth", slog.String("message", "user exists"))
		return fmt.Errorf("failed to create user or user exists")
	}

	user := models.User{
		Username:            strings.SplitN(googleUser.Name, " ", 2)[0],
		Email:               googleUser.Email,
		OauthProvider:       "google",
		ID:                  uuid.New(),
		OauthProviderUserID: googleUser.ID,
		IsAdmin:             false,
	}
	as.users = append(as.users, user)
	as.logger.Info("created new user with oauth2",
		slog.String("id", user.ID.String()),
		slog.String("username", user.Username),
		slog.String("email", user.Email))
	return as.SaveToFile()

}

func (as *authService) OauthUserExists(googleUser models.GoogleUserInfo) (models.User, error) {
	for _, user := range as.users {
		if user.Email == googleUser.Email || user.OauthProviderUserID == googleUser.ID {
			return user, nil
		}
	}
	return models.User{}, fmt.Errorf("user not found")
}

func (as *authService) IsAdmin(id string) bool {
	for _, user := range as.users {
		if user.ID.String() == id {
			return true
		}
	}
	return false
}
