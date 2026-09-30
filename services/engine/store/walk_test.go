// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"io/fs"
	"path/filepath"
)

func filepathWalk(root string, fn func(string)) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			fn(p)
		}
		return nil
	})
}
