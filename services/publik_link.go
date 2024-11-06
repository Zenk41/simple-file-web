package services

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Zenk41/simple-file-web/models"
)

type PublicLinkManager interface {
	CreatePublicLink(payload models.PublicLink) error
	ReadPublicLinks() []models.PublicLink
	UpdatePublicLink(id string, updated models.PublicLink) error
	DeletePublicLink(id string) error
	CheckIfRootPublic(bucket, path string) bool
	CheckSecurity(bucket, path, accessKey string) models.Security
	SearchPublicLinks(query string) []models.PublicLink
	GetRootByLink(link string) (models.PublicLink, error)
	SaveToFile() error
	LoadFromFile() error
	IsLinkDuplicate(link, id string) bool
}

type dataPublic struct {
	links    []models.PublicLink
	logger   *slog.Logger
	filename string
}

func NewDataPublic(logger *slog.Logger, filename string) PublicLinkManager {
	dp := &dataPublic{
		links:    []models.PublicLink{},
		logger:   logger,
		filename: filename,
	}
	err := dp.LoadFromFile()
	if err != nil {
		logger.Warn("Failed to load data from file", slog.String("error", err.Error()))
	}
	return dp
}

func (dp *dataPublic) SaveToFile() error {
	data, err := json.MarshalIndent(dp.links, "", "  ")
	if err != nil {
		dp.logger.Error("Failed to marshal public links", slog.String("error", err.Error()))
		return err
	}

	err = ioutil.WriteFile(dp.filename, data, 0644)
	if err != nil {
		dp.logger.Error("Failed to write public links to file", slog.String("error", err.Error()))
		return err
	}

	dp.logger.Info("Saved public links to file", slog.String("filename", dp.filename))
	return nil
}

func (dp *dataPublic) LoadFromFile() error {
	_, err := os.Stat(dp.filename)
	if os.IsNotExist(err) {
		dp.logger.Info("Database file does not exist, creating a new one", slog.String("filename", dp.filename))
		return dp.SaveToFile()
	}

	data, err := ioutil.ReadFile(dp.filename)
	if err != nil {
		dp.logger.Error("Failed to read public links from file", slog.String("error", err.Error()))
		return err
	}

	err = json.Unmarshal(data, &dp.links)
	if err != nil {
		dp.logger.Error("Failed to unmarshal public links", slog.String("error", err.Error()))
		return err
	}

	dp.logger.Info("Loaded public links from file", slog.String("filename", dp.filename), slog.Int("count", len(dp.links)))
	return nil
}

func (dp *dataPublic) CreatePublicLink(payload models.PublicLink) error {
	if dp.IsLinkDuplicate(payload.Link, "") {
		return fmt.Errorf("link is duplicate")
	}
	payload.ID = fmt.Sprintf("%d", len(dp.links)+1)
	payload.CreatedAt = time.Now()
	payload.UpdatedAt = time.Now()
	dp.links = append(dp.links, payload)
	dp.logger.Info("Created new public link",
		slog.String("id", payload.ID),
		slog.String("link", payload.Link),
		slog.String("bucket", payload.RealRootBucket),
		slog.String("path", payload.RealRootPath))
	return dp.SaveToFile()
}

func (dp *dataPublic) ReadPublicLinks() []models.PublicLink {
	dp.logger.Info("Retrieved all public links", slog.Int("count", len(dp.links)))
	return dp.links
}

func (dp *dataPublic) UpdatePublicLink(id string, updated models.PublicLink) error {
	for i, link := range dp.links {
		if link.ID == id {
			updated.ID = link.ID
			updated.CreatedAt = link.CreatedAt
			updated.UpdatedAt = time.Now()
			dp.links[i] = updated
			dp.logger.Info("Updated public link",
				slog.String("id", id),
				slog.String("link", updated.Link),
				slog.String("bucket", updated.RealRootBucket),
				slog.String("path", updated.RealRootPath))
			return dp.SaveToFile()
		}
	}
	dp.logger.Warn("Failed to update public link: not found", slog.String("id", id))
	return fmt.Errorf("public link with ID %s not found", id)
}

func (dp *dataPublic) DeletePublicLink(id string) error {
	for i, link := range dp.links {
		if link.ID == id {
			dp.links = append(dp.links[:i], dp.links[i+1:]...)
			dp.logger.Info("Deleted public link", slog.String("id", id))
			return dp.SaveToFile()
		}
	}
	dp.logger.Warn("Failed to delete public link: not found", slog.String("id", id))
	return fmt.Errorf("public link with ID %s not found", id)
}

func (dp *dataPublic) CheckIfRootPublic(bucket, path string) bool {
	for _, link := range dp.links {
		if link.RealRootBucket == bucket && link.RealRootPath == path {
			dp.logger.Info("Root checked as public",
				slog.String("bucket", bucket),
				slog.String("path", path))
			return true
		}
	}
	dp.logger.Info("Root checked as not public",
		slog.String("bucket", bucket),
		slog.String("path", path))
	return false
}

func (dp *dataPublic) CheckSecurity(bucket, path, accessKey string) models.Security {
	for _, link := range dp.links {
		if link.RealRootBucket == bucket && link.RealRootPath == path {
			isPermitted := (link.AccessKey == "" && link.AccessType == "PUBLIC" && link.Privacy == "READ") ||
				(link.AccessKey == accessKey)
			security := models.Security{
				AccessType:  link.AccessType,
				Privacy:     link.Privacy,
				IsPermitted: isPermitted,
			}
			dp.logger.Info("Security check performed",
				slog.String("bucket", bucket),
				slog.String("path", path),
				slog.Bool("isPermitted", isPermitted),
				slog.String("accessType", security.AccessType),
				slog.String("privacy", security.Privacy))
			return security
		}
	}
	dp.logger.Warn("Security check failed: link not found",
		slog.String("bucket", bucket),
		slog.String("path", path))
	return models.Security{IsPermitted: false}
}

func (dp *dataPublic) SearchPublicLinks(query string) []models.PublicLink {
	var results []models.PublicLink
	for _, link := range dp.links {
		if strings.Contains(link.Link, query) ||
			strings.Contains(link.RealRootPath, query) ||
			strings.Contains(link.Privacy, query) {
			results = append(results, link)
		}
	}
	dp.logger.Info("Searched for public links",
		slog.String("query", query),
		slog.Int("resultsCount", len(results)))
	return results
}

func (dp *dataPublic) IsLinkDuplicate(link, id string) bool {
	// For create (no ID provided) - check if link exists anywhere
	if id == "" {
		for _, l := range dp.links {
			if link == l.Link {
				return true
			}
		}
		return false
	}

	// For update (ID provided) - check if link exists under different ID
	for _, l := range dp.links {
		if link == l.Link && id != l.ID {
			return true
		}
	}
	return false
}

func (dp *dataPublic) GetRootByLink(link string) (models.PublicLink, error) {
	for _, l := range dp.links {
		if link == l.Link {
			dp.logger.Info("Retrieved root by link",
				slog.String("link", link),
				slog.String("bucket", l.RealRootBucket),
				slog.String("path", l.RealRootPath))
			return l, nil
		}
	}
	dp.logger.Warn("Failed to get root by link: not found", slog.String("link", link))
	return models.PublicLink{}, fmt.Errorf("link not found")
}
