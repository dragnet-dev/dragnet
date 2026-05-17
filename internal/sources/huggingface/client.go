package huggingface

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const hfAPIBase = "https://huggingface.co/api"

// hfModel is the API representation of a Hugging Face model.
type hfModel struct {
	ID           string    `json:"id"`
	LastModified time.Time `json:"lastModified"`
	Downloads    int64     `json:"downloads"`
	Siblings     []struct {
		Filename string `json:"rfilename"`
	} `json:"siblings"`
}

// popularModelEntry is one entry in state/popular_models.json.
type popularModelEntry struct {
	Name      string `json:"name"`
	Downloads int64  `json:"downloads"`
}

type popularModelList struct {
	Generated time.Time           `json:"generated"`
	Models    []popularModelEntry `json:"models"`
}

// Client fetches Hugging Face model anomalies.
type Client struct {
	http        *http.Client
	popularPath string
}

func New(popularPath string) *Client {
	return &Client{
		http:        &http.Client{Timeout: 30 * time.Second},
		popularPath: popularPath,
	}
}

func (c *Client) Name() string { return "huggingface" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	popular, err := c.loadPopularModels()
	if err != nil {
		log.Printf("[huggingface] load popular models: %v", err)
	}
	if len(popular) == 0 {
		// Bootstrap: pull the current top-200 by downloads from the HF API on
		// the fly. Without this, an empty popular set caused the source to
		// silently skip every recent model (filter below) and emit 0
		// incidents — a long-standing silent failure.
		bootstrapped, bErr := c.bootstrapPopular(ctx, 200)
		if bErr != nil {
			log.Printf("[huggingface] bootstrap popular models: %v", bErr)
		} else {
			popular = bootstrapped
			if saveErr := c.savePopularModels(popular); saveErr != nil {
				log.Printf("[huggingface] save bootstrapped models: %v", saveErr)
			}
			log.Printf("[huggingface] bootstrapped popular list with %d models", len(popular))
		}
	}
	popularSet := make(map[string]bool, len(popular))
	for _, m := range popular {
		popularSet[strings.ToLower(m.Name)] = true
	}

	models, err := c.recentModels(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("fetch recent models: %w", err)
	}

	var incidents []*incident.Incident
	for _, model := range models {
		// Only analyse models that are in the popular list (avoids noise from obscure models).
		if len(popular) > 0 && !popularSet[strings.ToLower(model.ID)] {
			continue
		}
		indicators := c.analyzeModel(model)
		if len(indicators) == 0 {
			continue
		}

		inc := modelToIncident(model, indicators)
		incidents = append(incidents, inc)
		log.Printf("[huggingface] anomaly detected in %s (%d signals)", model.ID, len(indicators))
	}
	return incidents, nil
}

// recentModels fetches models modified after since from the HF Hub API.
func (c *Client) recentModels(ctx context.Context, since time.Time) ([]hfModel, error) {
	url := hfAPIBase + "/models?sort=lastModified&direction=-1&limit=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HF API returned %d", resp.StatusCode)
	}

	var models []hfModel
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, err
	}

	if since.IsZero() {
		return models, nil
	}
	var filtered []hfModel
	for _, m := range models {
		if !m.LastModified.Before(since) {
			filtered = append(filtered, m)
		}
	}
	return filtered, nil
}

// analyzeModel inspects a model's file list for security anomaly signals.
func (c *Client) analyzeModel(model hfModel) []incident.ModelIndicator {
	var indicators []incident.ModelIndicator

	var hasSafetensors, hasBinary bool
	var binaryFiles []string
	for _, s := range model.Siblings {
		f := strings.ToLower(s.Filename)
		if strings.HasSuffix(f, ".safetensors") {
			hasSafetensors = true
		}
		if strings.HasSuffix(f, ".bin") || strings.HasSuffix(f, ".pt") {
			hasBinary = true
			binaryFiles = append(binaryFiles, s.Filename)
		}
	}

	if hasSafetensors && hasBinary {
		indicators = append(indicators, incident.ModelIndicator{
			Type:        "format_downgrade",
			Description: "Model distributes both safetensors and binary format files; binary files may execute arbitrary code on load.",
			Sources:     []string{"huggingface"},
			Confidence:  0.75,
		})
	} else if hasBinary && !hasSafetensors {
		for _, f := range binaryFiles {
			indicators = append(indicators, incident.ModelIndicator{
				Type:       "unexpected_binary",
				Filename:   f,
				Sources:    []string{"huggingface"},
				Confidence: 0.60,
			})
		}
	}

	return indicators
}

func modelToIncident(model hfModel, indicators []incident.ModelIndicator) *incident.Incident {
	attackType := "malicious_publish"
	for _, ind := range indicators {
		if ind.Type == "format_downgrade" {
			attackType = "model_poisoning"
			break
		}
	}

	inc := &incident.Incident{
		ID:          "huggingface-" + strings.ReplaceAll(model.ID, "/", "-"),
		Source:      "huggingface",
		AttackType:  attackType,
		Severity:    "high",
		Description: fmt.Sprintf("Security anomaly detected in Hugging Face model %s.", model.ID),
		Packages: []incident.Package{
			{Name: model.ID, Ecosystem: "huggingface"},
		},
		References: []string{
			"https://huggingface.co/" + model.ID,
		},
		Indicators: incident.Indicators{
			ModelIndicators: indicators,
		},
	}

	// Collect suspicious filenames into FileNames for downstream IOC export.
	for _, ind := range indicators {
		if ind.Filename != "" {
			inc.Indicators.FileNames = append(inc.Indicators.FileNames, ind.Filename)
		}
	}

	return inc
}

func (c *Client) loadPopularModels() ([]popularModelEntry, error) {
	data, err := os.ReadFile(c.popularPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list popularModelList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list.Models, nil
}

// bootstrapPopular fetches the top-N HF models by download count from the
// public API. Used to seed the popular set on first run when popular_models.json
// hasn't been written yet, removing the silent-empty-popular failure mode.
func (c *Client) bootstrapPopular(ctx context.Context, n int) ([]popularModelEntry, error) {
	url := fmt.Sprintf("%s/models?sort=downloads&direction=-1&limit=%d", hfAPIBase, n)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HF API returned %d", resp.StatusCode)
	}
	var raw []struct {
		ID        string `json:"id"`
		Downloads int64  `json:"downloads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]popularModelEntry, 0, len(raw))
	for _, r := range raw {
		out = append(out, popularModelEntry{Name: r.ID, Downloads: r.Downloads})
	}
	return out, nil
}

// savePopularModels writes the popular list back to disk so subsequent runs
// can skip the bootstrap fetch.
func (c *Client) savePopularModels(models []popularModelEntry) error {
	if c.popularPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.popularPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(popularModelList{
		Generated: time.Now().UTC(),
		Models:    models,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.popularPath, data, 0o644)
}
