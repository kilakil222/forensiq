// LZNT1 decompression for NTFS-compressed files.
// Algorithm: https://msdn.microsoft.com/en-us/library/jj665697.aspx (2.5)
// Adapted from velocidex/go-ntfs (Apache 2.0); debug logging removed.

package ntfs

import (
	"encoding/binary"
	"errors"
)

const (
	lznt1CompressedMask = uint16(1 << 15)
	lznt1SizeMask       = uint16(1<<12) - 1
)

var (
	errLZNT1ShiftTooLarge = errors.New("lznt1: shift too large")
	errLZNT1BlockTooSmall = errors.New("lznt1: block too small")
)

func lznt1GetDisplacement(offset uint16) byte {
	result := byte(0)
	for {
		if offset < 0x10 {
			return result
		}
		offset >>= 1
		result++
	}
}

// LZNT1Decompress decompresses an LZNT1 byte stream into the original
// uncompressed data. A compression unit may contain multiple chunks; the
// function reads chunks until input is exhausted or a chunk header is zero.
func LZNT1Decompress(in []byte) ([]byte, error) {
	i := 0
	out := make([]byte, 0, len(in)*4)
	for {
		if len(in) < i+2 {
			break
		}
		uncompressedChunkOffset := len(out)
		blockOffset := i
		blockHeader := binary.LittleEndian.Uint16(in[i:])
		i += 2

		size := int(blockHeader & lznt1SizeMask)
		blockEnd := blockOffset + size + 3
		if size == 0 {
			break
		}
		if len(in) < i+size {
			return nil, errLZNT1BlockTooSmall
		}
		if blockHeader&lznt1CompressedMask != 0 {
			for i < blockEnd {
				header := uint8(in[i])
				i++
				for maskIdx := uint8(0); maskIdx < 8 && i < blockEnd; maskIdx++ {
					if (header & 1) == 0 {
						out = append(out, in[i])
						i++
					} else {
						pointer := binary.LittleEndian.Uint16(in[i:])
						i += 2
						displacement := lznt1GetDisplacement(uint16(len(out) - uncompressedChunkOffset - 1))
						symbolOffset := int(pointer>>(12-displacement)) + 1
						symbolLength := int(pointer&(0xFFF>>displacement)) + 2
						startOffset := len(out) - symbolOffset
						for j := 0; j < symbolLength+1; j++ {
							idx := startOffset + j
							if idx < 0 || idx >= len(out) {
								return out, errLZNT1ShiftTooLarge
							}
							out = append(out, out[idx])
						}
					}
					header >>= 1
				}
			}
		} else {
			out = append(out, in[i:i+size+1]...)
			i += size + 1
		}
	}
	return out, nil
}
