// Package machineid returns an identifier that is stable for one machine and
// different on every other one. The capture store mixes it into its key, so a
// copied vault folder does not open captures on a second machine even when the
// master key is known there.
//
// The id is read from the operating system on every call. It is never cached
// on disk (a cache inside the vault folder would travel with a copy and defeat
// the lock) and no environment variable can override it.
package machineid

import "errors"

// ErrUnavailable means this machine exposes no usable id. Callers must keep
// working without the lock rather than fail.
var ErrUnavailable = errors.New("vaultmcp: no machine id available")
