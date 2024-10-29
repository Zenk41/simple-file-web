package config

import (
	"log/slog"
	"time"

	"github.com/spf13/viper"
)

// SetupViper initializes a new Viper instance with default values and environment variables
func SetupViper() *viper.Viper {
	v := viper.New()

	env := viper.GetString("APP_ENV")
	if env == "" {
		slog.Info("USE DEVELOPMET ENV")
		env = "development"
	}
	// Set default values
	v.SetDefault("PORT", "3000")
	v.SetDefault("DOWNLOAD_URL_EXPIRATION", 1*time.Hour)

	// Read from environment variables
	v.AutomaticEnv()
	return v
}
