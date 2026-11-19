package tray

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

// TestIconDataValid 验证 ICO 结构合法、内嵌 PNG 可解码。
func TestIconDataValid(t *testing.T) {
	for name, ico := range map[string][]byte{"green": greenIconData(), "red": redIconData()} {
		if len(ico) < 22 {
			t.Fatalf("%s: ICO 过小", name)
		}
		if ico[0] != 0 || ico[1] != 0 || ico[2] != 1 || ico[3] != 0 {
			t.Fatalf("%s: ICONDIR 非法", name)
		}
		if cnt := binary.LittleEndian.Uint16(ico[4:6]); cnt != 1 {
			t.Fatalf("%s: 条目数=%d", name, cnt)
		}
		size := binary.LittleEndian.Uint32(ico[14:18])
		offset := binary.LittleEndian.Uint32(ico[18:22])
		if offset != 22 || int(offset+size) != len(ico) {
			t.Fatalf("%s: offset=%d size=%d len=%d", name, offset, size, len(ico))
		}
		if _, err := png.Decode(bytes.NewReader(ico[offset:])); err != nil {
			t.Fatalf("%s: 内嵌 PNG 解码失败: %v", name, err)
		}
	}
}
