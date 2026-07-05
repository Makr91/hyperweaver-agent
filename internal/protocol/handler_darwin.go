package protocol

/*
#cgo LDFLAGS: -framework Cocoa
void hwaInstallURLHandler(void);
*/
import "C"

// urlCallback receives raw (still-unvalidated) URIs from the Apple Event
// handler; package-level because cgo exports cannot capture closures.
var urlCallback func(uri string)

// InstallURLHandler registers the in-process receiver for hwa:// invocations.
// macOS delivers a kAEGetURL Apple Event to the RUNNING application instance
// (registered via CFBundleURLTypes in Info.plist) instead of spawning a new
// process, so no HTTP handoff is involved on this platform. Must be called
// before the AppKit run loop starts (tray.Run) so an event that launched the
// app cold is not dropped.
func InstallURLHandler(cb func(uri string)) {
	urlCallback = cb
	C.hwaInstallURLHandler()
}

//export hwaHandleURL
func hwaHandleURL(uri *C.char) {
	if urlCallback != nil {
		urlCallback(C.GoString(uri))
	}
}
