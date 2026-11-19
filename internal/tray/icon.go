// tray 图标生成：运行时绘制盾牌图形并封装为 ICO（无需外部资源文件）。
package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"sync"
)

var (
	icoOnce    sync.Once
	icoGreen   []byte
	icoRed     []byte
)

func greenIconData() []byte {
	icoOnce.Do(buildIcons)
	return icoGreen
}

func redIconData() []byte {
	icoOnce.Do(buildIcons)
	return icoRed
}

func buildIcons() {
	icoGreen = icoBytes(drawShield(color.RGBA{22, 163, 74, 255}, color.RGBA{22, 101, 52, 255}))
	icoRed = icoBytes(drawShield(color.RGBA{220, 38, 38, 255}, color.RGBA{153, 27, 27, 255}))
}

// drawShield 画一个 64x64 盾牌 + 白色对勾。fill 为主色，edge 为描边色。
func drawShield(fill, edge color.RGBA) image.Image {
	const S = 64
	img := image.NewRGBA(image.Rect(0, 0, S, S))

	// 盾牌轮廓（顺时针）
	pts := [][2]float64{
		{32, 5}, {54, 13}, {54, 30}, {48, 43}, {32, 59}, {16, 43}, {10, 30}, {10, 13},
	}
	white := color.RGBA{255, 255, 255, 255}

	for y := 0; y < S; y++ {
		for x := 0; x < S; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5
			if !inPoly(pts, px, py) {
				continue
			}
			// 距轮廓边缘近 → 描边色，否则填充色
			c := fill
			if distToPolyEdge(pts, px, py) < 2.0 {
				c = edge
			}
			// 对勾：两段折线
			if distToSeg(px, py, 21, 32, 28, 42) < 3.4 ||
				distToSeg(px, py, 28, 42, 44, 22) < 3.4 {
				c = white
			}
			img.Set(x, y, c)
		}
	}
	return img
}

// inPoly 射线法判断点是否在多边形内。
func inPoly(pts [][2]float64, x, y float64) bool {
	inside := false
	j := len(pts) - 1
	for i := 0; i < len(pts); i++ {
		xi, yi := pts[i][0], pts[i][1]
		xj, yj := pts[j][0], pts[j][1]
		if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
			inside = !inside
		}
		j = i
	}
	return inside
}

// distToPolyEdge 点到多边形各边的最小距离。
func distToPolyEdge(pts [][2]float64, x, y float64) float64 {
	min := 1e9
	j := len(pts) - 1
	for i := 0; i < len(pts); i++ {
		d := distToSeg(x, y, pts[j][0], pts[j][1], pts[i][0], pts[i][1])
		if d < min {
			min = d
		}
		j = i
	}
	return min
}

// distToSeg 点到线段距离。
func distToSeg(px, py, x1, y1, x2, y2 float64) float64 {
	dx, dy := x2-x1, y2-y1
	l2 := dx*dx + dy*dy
	if l2 == 0 {
		return math.Hypot(px-x1, py-y1)
	}
	t := ((px-x1)*dx + (py-y1)*dy) / l2
	t = math.Min(1, math.Max(0, t))
	return math.Hypot(px-(x1+t*dx), py-(y1+t*dy))
}

// icoBytes 把 PNG 图像封装成单帧 ICO（Vista+ 支持 PNG 条目）。
func icoBytes(img image.Image) []byte {
	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)
	data := pngBuf.Bytes()

	buf := &bytes.Buffer{}
	buf.Write([]byte{0, 0, 1, 0, 1, 0}) // ICONDIR: reserved=0, type=icon, count=1
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	buf.Write([]byte{byte(w), byte(h), 0, 0}) // 宽/高/色板数/保留
	_ = binary.Write(buf, binary.LittleEndian, uint16(1))  // 色平面数
	_ = binary.Write(buf, binary.LittleEndian, uint16(32)) // 位深度
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	_ = binary.Write(buf, binary.LittleEndian, uint32(22)) // 数据偏移 = 6+16
	buf.Write(data)
	return buf.Bytes()
}
