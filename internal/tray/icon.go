package tray

import (
	"bytes"
	_ "embed"
	"image"
	"image/png"
	"runtime"

	xdraw "golang.org/x/image/draw"
)

// The tray uses the same artwork users see as the Hyperweaver UI favicon.
// Both files are copied verbatim from the hyperweaver-ui repo's public/
// assets (favicon.ico and images/logo192.png).

//go:embed assets/icon.ico
var iconICO []byte

//go:embed assets/icon.png
var iconPNG []byte

// iconBytes returns the tray icon in the format the current OS requires:
// a real .ico on Windows, PNG elsewhere. macOS menu-bar icons render at
// their natural pixel size, so the 192px logo is downscaled there.
func iconBytes() ([]byte, error) {
	switch runtime.GOOS {
	case "windows":
		return iconICO, nil
	case "darwin":
		return scaledPNG(iconPNG, 22)
	default:
		return iconPNG, nil
	}
}

// scaledPNG decodes a PNG and scales it to size x size pixels.
func scaledPNG(data []byte, size int) ([]byte, error) {
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), xdraw.Over, nil)

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
