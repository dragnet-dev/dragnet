package cmd

import (
	"context"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/container"
	"github.com/dragnet-dev/dragnet/internal/popularity"
	"github.com/dragnet-dev/dragnet/internal/sources/docker_hub"
	"github.com/dragnet-dev/dragnet/internal/state"
	"github.com/spf13/cobra"
)

var updatePopularCmd = &cobra.Command{
	Use:   "update-popular",
	Short: "Refresh popular packages lists used for typosquat detection",
	RunE:  runUpdatePopular,
}

var (
	popularModule    string
	popularEcosystem string
	popularCount     int
)

func init() {
	updatePopularCmd.Flags().StringVar(&popularModule, "module", "supply",
		"Module whose ecosystems to update")
	updatePopularCmd.Flags().StringVar(&popularEcosystem, "ecosystem", "",
		"Comma-separated ecosystems to update (default: all from module config)")
	updatePopularCmd.Flags().IntVar(&popularCount, "count", 10000,
		"Number of top packages to fetch per ecosystem")
}

func runUpdatePopular(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	stateMgr := state.New()
	st, err := stateMgr.Load(filepath.Join(dataDir(), "state/last_sync.json"))
	if err != nil {
		return err
	}
	if st.PopularPackagesLastUpdated == nil {
		st.PopularPackagesLastUpdated = make(map[string]time.Time)
	}

	ctx := context.Background()

	// Container module: fetch popular Docker Hub images instead of package lists.
	if popularModule == "container" {
		return runUpdatePopularImages(ctx, cfg, stateMgr, st)
	}

	modCfg, ok := cfg.Modules[popularModule]
	if !ok {
		log.Printf("[update-popular] unknown module %q", popularModule)
		return nil
	}

	ecosystems := modCfg.Ecosystems
	if popularEcosystem != "" {
		ecosystems = strings.Split(popularEcosystem, ",")
	}

	for _, eco := range ecosystems {
		log.Printf("[update-popular] fetching top %d packages for %s", popularCount, eco)
		pkgs, err := popularity.FetchPopularPackages(ctx, eco, popularCount)
		if err != nil {
			log.Printf("[update-popular] %s: %v (skipping)", eco, err)
			continue
		}
		if len(pkgs) == 0 {
			log.Printf("[update-popular] %s: no packages returned (ecosystem may not be supported)", eco)
			continue
		}
		if err := popularity.SavePopularList(filepath.Join(dataDir(), "state/popular_packages"), eco, pkgs); err != nil {
			log.Printf("[update-popular] save %s: %v", eco, err)
			continue
		}
		st.PopularPackagesLastUpdated[eco] = time.Now().UTC()
		log.Printf("[update-popular] %s: saved %d packages", eco, len(pkgs))
	}

	return stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), st)
}

func runUpdatePopularImages(ctx context.Context, cfg *config.Config, stateMgr *state.Manager, st *state.State) error {
	modCfg := cfg.Modules["container"]
	n := int(modCfg.PopularImageThreshold)
	if n <= 0 {
		n = 200 // reasonable default for "top N images"
	}
	// Cap n to a pagination-friendly size; Docker Hub returns max 100 per page.
	if n > 200 {
		n = 200
	}

	log.Printf("[update-popular] fetching top %d Docker Hub official images", n)
	raw, err := docker_hub.New().FetchPopular(ctx, n)
	if err != nil {
		return err
	}

	imgs := make([]container.PopularImage, 0, len(raw))
	for _, r := range raw {
		imgs = append(imgs, container.PopularImage{
			Repository:  r.Repository,
			WeeklyPulls: r.WeeklyPulls,
		})
	}

	path := filepath.Join(dataDir(), "state/popular_images.json")
	if err := container.SavePopularImages(path, imgs); err != nil {
		return err
	}

	now := time.Now().UTC()
	st.PopularImagesLastUpdated = &now
	log.Printf("[update-popular] saved %d popular images to %s", len(imgs), path)
	return stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), st)
}
