package walker

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/saracen/walker"

	"golang.org/x/xerrors"
)

// WalkDir walks the file tree rooted at root, calling WalkFunc for each file or
// directory in the tree, including root, but a directory to be ignored will be skipped.
func WalkDir(root string, f WalkFunc) error {
	// walk function called for every path found
	walkFn := func(pathname string, fi os.FileInfo) error {
		if !fi.Mode().IsRegular() && !fi.Mode().IsDir() {
			return nil
		}

		if isIgnored(pathname) {
			return filepath.SkipDir
		}
		pathname = filepath.Clean(pathname)
		if err := f(pathname, fi, fileOnceOpener(pathname)); err != nil {
			return xerrors.Errorf("failed to analyze file: %w", err)
		}
		return nil
	}

	// error function called for every error encountered
	errorCallbackOption := walker.WithErrorCallback(func(pathname string, err error) error {
		return nil
	})

	// Multiple goroutines stat the filesystem concurrently. The provided
	// walkFn must be safe for concurrent use.
	if err := walker.Walk(root, walkFn, errorCallbackOption); err != nil {
		return err
	}
	return nil
}

// fileOnceOpener opens a file once and the content is shared so that some analyzers can use the same data
func fileOnceOpener(filePath string) func() ([]byte, error) {
	var once sync.Once
	var b []byte
	var err error

	return func() ([]byte, error) {
		once.Do(func() {
			b, err = ioutil.ReadFile(filePath)
		})
		if err != nil {
			return nil, xerrors.Errorf("unable to read file: %w", err)
		}
		return b, nil
	}
}
