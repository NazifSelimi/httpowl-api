// Package migrations holds the goose SQL migrations, embedded into the API binary.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
