//go:build !darwin

package protocol

// InstallURLHandler is a no-op outside macOS: Windows and Linux deliver
// protocol invocations by spawning a new process with the URI as an argument
// (handled in main via URIFromArgs + Forward), never by messaging the
// running instance directly.
func InstallURLHandler(_ func(uri string)) {}
