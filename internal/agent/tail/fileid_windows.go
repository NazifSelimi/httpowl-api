//go:build windows

package tail

import "os"

// IIS rotates by new file name, so the name is enough on Windows.
func fileID(fi os.FileInfo) string { return fi.Name() }
