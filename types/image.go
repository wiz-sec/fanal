package types

import (
	"time"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

type OS struct {
	Family string
	Name   string
}

type Layer struct {
	Digest string `json:",omitempty"`
	DiffID string `json:",omitempty"`
}

type Package struct {
	Name            string `json:",omitempty"`
	Version         string `json:",omitempty"`
	Release         string `json:",omitempty"`
	Epoch           int    `json:",omitempty"`
	Arch            string `json:",omitempty"`
	SrcName         string `json:",omitempty"`
	SrcVersion      string `json:",omitempty"`
	SrcRelease      string `json:",omitempty"`
	SrcEpoch        int    `json:",omitempty"`
	Repository      string `json:",omitempty"`
	Modularitylabel string `json:",omitempty"`
	Layer           Layer  `json:",omitempty"`
}

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

type PackageInfo struct {
	FilePath string
	Packages []Package
}

type LibraryInfo struct {
	Library godeptypes.Library `json:",omitempty"`
	Layer   Layer              `json:",omitempty"`
}

type Application struct {
	Type      string
	FilePath  string
	Libraries []LibraryInfo
}

// ArtifactReference represents a reference of container image, local filesystem and repository
type ArtifactReference struct {
	Name        string // image name, tar file name, directory or repository name
	ID          string
	BlobIDs     []string
	RepoTags    []string
	RepoDigests []string
}

// ArtifactInfo is stored in cache
type ArtifactInfo struct {
	SchemaVersion int
	Architecture  string
	Created       time.Time
	DockerVersion string
	OS            string

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`
}

// BlobInfo is stored in cache
type BlobInfo struct {
	SchemaVersion int
	Digest        string        `json:",omitempty"`
	DiffID        string        `json:",omitempty"`
	OS            *OS           `json:",omitempty"`
	PackageInfos  []PackageInfo `json:",omitempty"`
	Applications  []Application `json:",omitempty"`
	OpaqueDirs    []string      `json:",omitempty"`
	WhiteoutFiles []string      `json:",omitempty"`
}

// ArtifactDetail is generated by applying blobs
type ArtifactDetail struct {
	OS           *OS           `json:",omitempty"`
	Packages     []Package     `json:",omitempty"`
	Applications []Application `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`
}
