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
)

type repositories struct {
	*sync.Mutex
	sources map[string][]string
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
		repositoriesStatic.sources = map[string][]string{}
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

		// Populates a map containing (package+version): repositories
		for _, p := range packages {
			id := packageIdentifierBuilder(p.Name, p.Version)
			repositoriesStatic.sources[id] = append(repositoriesStatic.sources[id], repository)
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

// findPackageSource searches each source for given package name and version
// Returns the source name if a match is found
func findPackageSource(name, version string) string {
	repos := repositoriesStatic.sources[packageIdentifierBuilder(name, version)]
	if len(repos) == 0 {
		return "Unknown"
	}

	return strings.Join(repos, ", ")
}

func packageIdentifierBuilder(name, version string) string {
	return fmt.Sprintf("%s::%s", name, version)
}
