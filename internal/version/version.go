// Package version holds the application version, stamped by release-please.
package version

// Version is the application version. release-please rewrites the value on
// every release; CI additionally overrides it via -ldflags -X for tagged builds.
var Version = "0.1.0" // x-release-please-version
