package tray

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
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

var badgeColor = color.NRGBA{R: 255, G: 0, B: 0, A: 255}

// Icon answers the tray image of the mode: the SHI mark while shiMode is true, the Hyperweaver mark otherwise, a red dot on it while unread is true; a .ico on Windows, a 22px PNG on macOS and the 192px PNG elsewhere.
func Icon(shiMode, unread bool) ([]byte, error) {
	ico, mark := hyperweaverICO, hyperweaverPNG
	if shiMode {
		ico, mark = shiICO, shiPNG
	}
	if unread {
		badged, err := badgedPNG(mark)
		if err != nil {
			return nil, err
		}
		mark = badged
		ico = icoFromPNG(mark)
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

func badgedPNG(data []byte) ([]byte, error) {
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	bounds := src.Bounds()
	dst := image.NewNRGBA(bounds)
	draw.Draw(dst, bounds, src, bounds.Min, draw.Src)
	size := bounds.Dx()
	radius := size / 6
	cx, cy := bounds.Max.X-radius-1, bounds.Min.Y+radius+size/16
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= radius*radius {
				dst.SetNRGBA(x, y, badgeColor)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func icoFromPNG(data []byte) []byte {
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	length := len(data)
	if length > math.MaxUint32 {
		return nil
	}
	size := uint32(length)
	dimension := func(v int) byte {
		if v > 0 && v < 256 {
			return byte(v)
		}
		return 0
	}
	var buf bytes.Buffer
	header := []any{uint16(0), uint16(1), uint16(1)}
	for _, field := range header {
		_ = binary.Write(&buf, binary.LittleEndian, field)
	}
	buf.WriteByte(dimension(config.Width))
	buf.WriteByte(dimension(config.Height))
	buf.WriteByte(0)
	buf.WriteByte(0)
	entry := []any{uint16(1), uint16(32), size, uint32(22)}
	for _, field := range entry {
		_ = binary.Write(&buf, binary.LittleEndian, field)
	}
	buf.Write(data)
	return buf.Bytes()
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
