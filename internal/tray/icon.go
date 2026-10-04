package tray

import (
	"bytes"
	_ "embed"
	"image"
	"image/png"
	"runtime"

	xdraw "golang.org/x/image/draw"
)

//go:embed assets/icon.ico
var hyperweaverICO []byte

//go:embed assets/icon.png
var hyperweaverPNG []byte

//go:embed assets/shi.ico
var shiICO []byte

//go:embed assets/shi.png
var shiPNG []byte

// Icon answers the tray image of the mode: the SHI mark while shiMode is true, the Hyperweaver mark otherwise, as a .ico on Windows, a 22px PNG on macOS and the 192px PNG elsewhere.
func Icon(shiMode bool) ([]byte, error) {
	ico, mark := hyperweaverICO, hyperweaverPNG
	if shiMode {
		ico, mark = shiICO, shiPNG
	}
	switch runtime.GOOS {
	case "windows":
		return ico, nil
	case "darwin":
		return scaledPNG(mark, 22)
	default:
		return mark, nil
	}
}

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
