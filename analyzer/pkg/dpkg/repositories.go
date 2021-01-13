package dpkg

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/fanal/types"
	mapset "github.com/deckarep/golang-set"
)

type repositories struct {
	*sync.Mutex
	// package name: versions: repos
	sources map[string]map[string]mapset.Set
}

var repositoriesStatic = &repositories{Mutex: &sync.Mutex{}}

const (
	sourcesFilePath      = "/var/lib/apt/lists"
	sourcesPackageSuffix = "_Packages"
)

// loadDpkgSourcesOnce tries one time to load Dpkg sources, this operation is thread-safe
func loadDpkgSourcesOnce() error {
	if repositoriesStatic.sources == nil {
		repositoriesStatic.Lock()
		defer repositoriesStatic.Unlock()

		// Check if sources were set while we waited the lock
		if repositoriesStatic.sources != nil {
			return nil
		}

		err := loadDpkgSources()
		if err != nil {
			return fmt.Errorf("error in a.loadDpkgSources(): %s", err)
		}
	}

	return nil
}

// loadDpkgSources loads Dpkg sources' packages for each repository
func loadDpkgSources() error {
	if repositoriesStatic.sources == nil {
		repositoriesStatic.sources = map[string]map[string]mapset.Set{}
	}

	err := filepath.Walk(sourcesFilePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk failed, path: %s, error: %w", path, err)
		}

		if !strings.HasSuffix(info.Name(), sourcesPackageSuffix) {
			return nil
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read source file %s, error in ioutil.ReadFile(): %w", info.Name(), err)
		}

		repository := strings.TrimSuffix(info.Name(), sourcesPackageSuffix)
		packages := parsePackagesFromArchive(content)

		// Append a repository for each package's version
		for _, p := range packages {
			// Get versions map
			versionReposMap, ok := repositoriesStatic.sources[p.Name]
			if !ok {
				versionReposMap = map[string]mapset.Set{}
				repositoriesStatic.sources[p.Name] = versionReposMap
			}

			// Get repositories set
			reposSet, ok := versionReposMap[p.Version]
			if !ok {
				reposSet = mapset.NewSet()
				versionReposMap[p.Version] = reposSet
			}

			reposSet.Add(repository)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error in filepath.Walk(): %w", err)
	}

	return nil
}

// parsePackagesFromArchive parses Dpkg packages from source archive's content
func parsePackagesFromArchive(content []byte) []*types.Package {
	var packages []*types.Package

	scanner := bufio.NewScanner(bytes.NewBuffer(content))

	// Iterate each pkg section
	for scanner.Scan() {
		// Verify our section is not empty
		if section := strings.TrimSpace(scanner.Text()); section == "" {
			continue
		}

		packages = append(packages, parsePackage(scanner))
	}

	return packages
}

// parsePackage parses package section
func parsePackage(scanner *bufio.Scanner) *types.Package {
	var pkg types.Package

	for {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}

		if strings.HasPrefix(line, "Package: ") {
			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimPrefix(line, "Version: ")
		} else if strings.HasPrefix(line, "Architecture: ") {
			pkg.Arch = strings.TrimPrefix(line, "Architecture: ")
		}

		if !scanner.Scan() {
			break
		}
	}

	return &pkg
}

const unknownRepository = "Unknown"

// findPackageSource searches each repo's source for given package name and version
// Returns the repo's source name if a match is found
func findPackageSource(name, version string) string {
	versionReposMap, ok := repositoriesStatic.sources[name]
	// Check if the package or versions are missing
	if !ok || len(versionReposMap) == 0 {
		return unknownRepository
	}

	// Check if we have the exact version's repositories
	reposSet, ok := versionReposMap[version]
	if ok && reposSet != nil {
		if repos := stringSetToSlice(reposSet); len(repos) > 0 {
			return strings.Join(repos, ", ")
		}
	}

	// If exact version's repositories are not found, extract repositories from any version
	for _, reposSet = range versionReposMap {
		if reposSet == nil {
			continue
		}

		if repos := stringSetToSlice(reposSet); len(repos) > 0 {
			return strings.Join(repos, ", ")
		}
	}

	return unknownRepository
}

func stringSetToSlice(set mapset.Set) []string {
	var slice []string

	for _, elem := range set.ToSlice() {
		slice = append(slice, elem.(string))
	}

	return slice
}
