package prefetch

import (
	"encoding/binary"
	"fmt"
)

// decompressMAM decompresses a Win10+ prefetch file in MAM (LZXPRESS Huffman) format.
func decompressMAM(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("MAM: too short (%d bytes)", len(data))
	}
	if data[0] != 'M' || data[1] != 'A' || data[2] != 'M' {
		return nil, fmt.Errorf("MAM: bad signature %02x%02x%02x", data[0], data[1], data[2])
	}
	uncompSize := int(binary.LittleEndian.Uint32(data[4:8]))
	if uncompSize <= 0 || uncompSize > 16*1024*1024 {
		return nil, fmt.Errorf("MAM: unreasonable uncompressed size %d", uncompSize)
	}
	return xpressHuffDecompress(data[8:], uncompSize)
}

// xpressHuffDecompress implements MS-XCA LZXPRESS Huffman decompression.
//
// Bit stream: LE uint16 words, MSB-first (bit 15 of each word is the first bit
// consumed).  The reference implementation (dissect) pre-loads 2 words (32 bits)
// and reloads when the buffer drops below 16 bits, keeping its source pointer
// always exactly 2 bytes ahead of our s.pos.  The mli=15 extra-length byte is
// therefore at s.pos+2 (one extra loadWord() away).
//
// Back-references use the ENTIRE accumulated output as the sliding window
// (not a per-chunk circular buffer), matching Windows RtlDecompressBufferEx.
func xpressHuffDecompress(src []byte, expectedSize int) ([]byte, error) {
	dst := make([]byte, 0, expectedSize)
	const chunkSize = 65536
	chunkBuf := make([]byte, chunkSize)

	for len(dst) < expectedSize {
		if len(src) < 256 {
			break
		}

		lengths := make([]uint8, 512)
		for i := 0; i < 256; i++ {
			lengths[i*2] = src[i] & 0x0f
			lengths[i*2+1] = (src[i] >> 4) & 0x0f
		}
		src = src[256:]

		for i := range chunkBuf {
			chunkBuf[i] = 0
		}

		root := buildHuffTrie(lengths)
		s := &xpressStream{data: src}
		chunkOut := 0
		limit := expectedSize - len(dst)
		if limit > chunkSize {
			limit = chunkSize
		}
		dstBase := len(dst)

		for chunkOut < chunkSize {
			sym, err := decodeHuff(root, s)
			if err != nil {
				break
			}

			if sym < 256 {
				chunkBuf[chunkOut] = byte(sym)
				chunkOut++
				if chunkOut >= limit {
					break
				}
				continue
			}

			sym -= 256
			numOffBits := sym >> 4
			mli := sym & 0x0f

			var offsetLow uint32
			var matchLen int

			if mli != 15 {
				var err error
				offsetLow, err = s.readBits(numOffBits)
				if err != nil {
					break
				}
				matchLen = int(mli) + 3
			} else {
				// Dissect/Windows maintains bits>=16 at all times via skip()'s
				// post-load.  Fill the buffer to bits>=16 before peeking offset
				// bits so that s.pos aligns with the reference source pointer.
				if s.bits < 16 {
					s.loadWord()
				}
				for s.bits < int(numOffBits) {
					s.loadWord()
				}
				offsetLow = uint32(s.buf >> uint(64-numOffBits))

				// All byte-stream reads happen BEFORE consuming the offset bits
				// (mirrors dissect: read(ex) → maybe read more → skip(numOffBits)).
				if s.pos >= len(s.data) {
					break
				}
				ex := int(s.data[s.pos])
				s.pos++
				if ex == 255 {
					if s.pos+1 >= len(s.data) {
						break
					}
					matchLen = int(s.data[s.pos]) | int(s.data[s.pos+1])<<8
					s.pos += 2
					matchLen += 3
				} else {
					matchLen = ex + 15 + 3
				}

				// Consume offset bits; post-load to restore bits>=16.
				s.buf <<= uint(numOffBits)
				s.bits -= int(numOffBits)
				if s.bits < 16 {
					s.loadWord()
				}
			}

			offset := int(uint(1)<<uint(numOffBits) | uint(offsetLow))

			// Copy from full output history (all previous chunks + current chunk).
			for i := 0; i < matchLen; i++ {
				absPos := dstBase + chunkOut - offset
				var b byte
				if absPos >= 0 {
					if absPos < dstBase {
						b = dst[absPos]
					} else {
						b = chunkBuf[absPos-dstBase]
					}
				}
				chunkBuf[chunkOut] = b
				chunkOut++
				if chunkOut >= limit {
					break
				}
			}
			if chunkOut >= limit {
				break
			}
		}

		if chunkOut > limit {
			chunkOut = limit
		}
		// Match dissect/Windows bits>=16 invariant at chunk boundaries: the
		// reference decoder always post-loads one word after the last skip(),
		// advancing its source pointer by 2 bytes past the minimum needed.
		// Without this the next chunk's code-length table is read 2 bytes early.
		if s.bits < 16 {
			s.loadWord()
		}
		dst = append(dst, chunkBuf[:chunkOut]...)
		src = src[s.consumed():]
	}

	if len(dst) > expectedSize {
		dst = dst[:expectedSize]
	}
	return dst, nil
}

// ── Huffman Trie ─────────────────────────────────────────────────────────────

type trieNode struct {
	sym   int
	child [2]*trieNode
}

// buildHuffTrie builds a canonical Huffman trie for MSB-first traversal.
func buildHuffTrie(lengths []uint8) *trieNode {
	maxLen := 0
	for _, l := range lengths {
		if int(l) > maxLen {
			maxLen = int(l)
		}
	}
	if maxLen == 0 {
		return &trieNode{sym: 0}
	}

	blCount := make([]int, maxLen+1)
	for _, l := range lengths {
		if l > 0 {
			blCount[l]++
		}
	}
	nextCode := make([]uint32, maxLen+2)
	code := uint32(0)
	for bits := 1; bits <= maxLen; bits++ {
		code = (code + uint32(blCount[bits-1])) << 1
		nextCode[bits] = code
	}

	root := &trieNode{sym: -1}
	for sym, l8 := range lengths {
		l := int(l8)
		if l == 0 {
			continue
		}
		c := nextCode[l]
		nextCode[l]++

		node := root
		for bit := 0; bit < l; bit++ {
			b := (c >> uint(l-1-bit)) & 1
			if node.child[b] == nil {
				node.child[b] = &trieNode{sym: -1}
			}
			node = node.child[b]
		}
		node.sym = sym
	}
	return root
}

func decodeHuff(root *trieNode, s *xpressStream) (int, error) {
	node := root
	for node.sym == -1 {
		bit, err := s.readBits(1)
		if err != nil {
			return 0, err
		}
		next := node.child[bit]
		if next == nil {
			return 0, fmt.Errorf("xpress: invalid huffman path")
		}
		node = next
	}
	return node.sym, nil
}

// ── Bit Stream ───────────────────────────────────────────────────────────────

// xpressStream reads LE uint16 words MSB-first (bit 15 of each word first).
// Valid bits occupy the TOP positions of buf (a 64-bit MSB-first accumulator).
type xpressStream struct {
	data []byte
	pos  int
	buf  uint64
	bits int
}

func (s *xpressStream) readBits(n int) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	for s.bits < n {
		if s.pos+1 < len(s.data) {
			word := uint64(s.data[s.pos]) | uint64(s.data[s.pos+1])<<8
			s.pos += 2
			s.buf |= word << uint(64-s.bits-16)
			s.bits += 16
		} else if s.pos < len(s.data) {
			s.buf |= uint64(s.data[s.pos]) << uint(64-s.bits-8)
			s.pos++
			s.bits += 8
		} else {
			return 0, fmt.Errorf("xpress: stream exhausted (need %d bits, have %d)", n, s.bits)
		}
	}
	val := uint32(s.buf >> uint(64-n))
	s.buf <<= uint(n)
	s.bits -= n
	return val, nil
}

// loadWord loads the next LE uint16 word from data[pos:pos+2] into the bit
// buffer without consuming bits.  Used by the mli=15 handler to load the
// "pre-loaded" word that the reference decoder has already buffered.
func (s *xpressStream) loadWord() {
	if s.pos+1 < len(s.data) {
		word := uint64(s.data[s.pos]) | uint64(s.data[s.pos+1])<<8
		s.pos += 2
		s.buf |= word << uint(64-s.bits-16)
		s.bits += 16
	}
}

// consumed returns the number of source bytes consumed for this chunk.
func (s *xpressStream) consumed() int {
	return s.pos
}
