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


