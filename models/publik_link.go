package models

import "time"

type PublicLink struct {
	ID   string `json:"id"`
	Link string `json:"link"`
	// PublicPath   string `json:"public_path"`
	RealRootBucket string `json:"real_root_bucket"`
	RealRootPath   string `json:"real_root_path"`
	AccessKey      string `json:"acccess_key"`
	AccessType     string `json:"access_type"`
	Privacy        string `json:"privacy"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Security struct {
	AccessType  string
	Privacy     string
	IsPermitted bool
}

type PayloadPublicLink struct {
	Link           string `json:"link" validate:"required, link"`
	RealRootBucket string `json:"real_root_bucket" validate:"required, bucket"`
	RealRootPath   string `json:"real_root_path" validate:"required, path"`
	AccessKey      string `json:"acccess_key" validate:"accesskey"`
	AccessType     string `json:"access_type"  validate:"required,accesstype"`
	Privacy        string `json:"privacy"  validate:"required,privacy"`
}

type Alert struct {
	Type    string
	Message string
}
