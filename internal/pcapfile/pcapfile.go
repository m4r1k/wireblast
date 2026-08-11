// Package pcapfile loads an Ethernet capture into a form the transmit loop can
// replay without allocating.
//
// It uses gopacket's pure-Go pcapgo reader, so Wireblast has no libpcap or cgo
// dependency and a static binary works anywhere.
//
// The whole file is read and validated before the dataplane starts. A broken
// or unsupported capture should cost you an error message, never a bounced
// link and a half-started run.
package pcapfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/atoonk/wireblast/internal/config"
)

// Limits on what will be loaded.
const (
	// MinFrame is the smallest thing that can be an Ethernet frame: two MAC
	// addresses and an EtherType.
	MinFrame = 14
	// MaxFrame is the largest frame that can be transmitted. A UMEM frame is
	// at most a page, so anything above that is chained across several; this
	// stays comfortably inside how many frames one packet may span, and
	// preflight rejects a capture that does not.
	MaxFrame = 16384
	// DefaultMaxBytes is the memory budget a capture may occupy when the
	// caller does not choose one. The whole capture is held in RAM (which this
	// runs as root on), so an unbounded load could OOM the host before the NIC
	// is ever touched; anyone with more memory can raise the budget with
	// --pcap-memory.
	DefaultMaxBytes = 1 << 30 // 1 GiB
	// recordBytes is what one index entry costs against the budget. A test
	// asserts it matches unsafe.Sizeof(record{}), so the accounting cannot
	// drift from the real struct. Charging the index means the budget also
	// bounds packet count: a capture of nothing but minimum-size frames costs
	// MinFrame+recordBytes per packet.
	recordBytes = 24
)

// Limits is what the caller allows Load to hold in memory. The zero value
// means the defaults.
type Limits struct {
	// MaxBytes is the memory budget for the capture, counting frame bytes and
	// the per-frame index. Zero means DefaultMaxBytes.
	MaxBytes uint64
}

// record is one frame's place in the flat backing store. len fits a uint32
// because no frame exceeds MaxFrame; off is a uint64 so a raised memory
// budget can hold captures past 4 GiB.
type record struct {
	off uint64
	len uint32
	// gap is the time between the previous frame and this one, as the capture
	// recorded it. Zero for the first frame.
	gap time.Duration
}

// File is a loaded capture, ready to replay.
//
// Frames live in one contiguous byte slice with an index alongside, so replay
// is a slice expression and a copy — no per-packet allocation, and the frames
// stay adjacent in memory for the cache's benefit.
type File struct {
	path string

	data []byte
	recs []record

	minLen, maxLen int
	meanLen        int
	span           time.Duration

	// truncated counts records whose captured bytes were fewer than the
	// original packet length, i.e. cut short by the capture's snaplen.
	truncated int
	// skipped counts records that could not be replayed at all.
	skipped int
}

// Load reads and validates a capture file.
func Load(path string, lim Limits) (*File, error) {
	maxBytes := lim.MaxBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	// Slice lengths are ints, so on a 32-bit platform the budget can never
	// exceed what a slice can address anyway.
	maxBytes = min(maxBytes, math.MaxInt)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture: %w", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 1<<20)
	src, linkType, err := openReader(r, path)
	if err != nil {
		return nil, err
	}
	if linkType != layers.LinkTypeEthernet {
		return nil, fmt.Errorf(
			"%s has link type %v, but Wireblast can only replay Ethernet captures. "+
				"Re-capture with an Ethernet interface, or convert the file first", path, linkType)
	}

	out := &File{path: path, minLen: MaxFrame + 1}
	var fileSize int64
	if st, err := f.Stat(); err == nil {
		fileSize = st.Size()
	}
	// The file size is a close overestimate of the frame bytes (per-record
	// headers and all), so growing the store by append would peak at roughly
	// twice the final size for nothing. Reserve once up front instead.
	if fileSize > 0 {
		out.data = make([]byte, 0, min(uint64(fileSize), maxBytes))
	}
	var first, prev time.Time
	for i := 0; ; i++ {
		data, ci, err := src.ZeroCopyReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A trailing partial record is common in a capture that was cut
			// off; anything else is worth reporting with its position.
			if errors.Is(err, io.ErrUnexpectedEOF) && len(out.recs) > 0 {
				out.skipped++
				break
			}
			return nil, fmt.Errorf("%s: reading packet %d: %w", path, i+1, err)
		}
		if uint64(len(out.data)+len(data))+uint64(len(out.recs)+1)*recordBytes > maxBytes {
			return nil, fmt.Errorf("%s needs more than %s of memory to load (frame bytes plus "+
				"index). Raise the budget with --pcap-memory %s, or trim the capture with "+
				"`editcap -c N` to keep fewer packets",
				path, config.FormatSize(maxBytes), config.FormatSize(suggestBudget(fileSize, maxBytes)))
		}

		switch {
		case len(data) < MinFrame:
			return nil, fmt.Errorf("%s: packet %d is %d bytes, too short to be an Ethernet frame",
				path, i+1, len(data))
		case len(data) > MaxFrame:
			return nil, fmt.Errorf("%s: packet %d is %d bytes, larger than the %d-byte maximum "+
				"Wireblast can transmit", path, i+1, len(data), MaxFrame)
		}
		if ci.Length > len(data) {
			out.truncated++
		}

		gap := time.Duration(0)
		if !prev.IsZero() && !ci.Timestamp.IsZero() {
			if d := ci.Timestamp.Sub(prev); d > 0 {
				gap = d
			}
		}
		if !ci.Timestamp.IsZero() {
			if first.IsZero() {
				first = ci.Timestamp
			}
			prev = ci.Timestamp
		}

		out.recs = append(out.recs, record{off: uint64(len(out.data)), len: uint32(len(data)), gap: gap})
		out.data = append(out.data, data...)
		out.minLen = min(out.minLen, len(data))
		out.maxLen = max(out.maxLen, len(data))
	}

	if len(out.recs) == 0 {
		return nil, fmt.Errorf("%s contains no packets", path)
	}
	if !first.IsZero() && !prev.IsZero() {
		out.span = prev.Sub(first)
	}
	out.meanLen = len(out.data) / len(out.recs)
	return out, nil
}

// suggestBudget picks a clean power-of-two budget the failed capture should
// fit inside, for the over-budget error message.
func suggestBudget(fileSize int64, maxBytes uint64) uint64 {
	// The index costs a little more per record than the pcap's own framing, so
	// 1.3x the file size covers even a capture of minimum-size frames.
	need := maxBytes * 2
	if fileSize > 0 {
		need = uint64(float64(fileSize) * 1.3)
	}
	s := uint64(1) << 20
	for s < need && s < 1<<62 {
		s <<= 1
	}
	return s
}

// openReader picks the pcap or pcapng reader by sniffing the file's magic.
func openReader(r *bufio.Reader, path string) (packetReader, layers.LinkType, error) {
	magic, err := r.Peek(4)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	// pcapng section header block; everything else is classic pcap, whose own
	// reader rejects a bad magic with a clear message.
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		ng, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: not a readable pcapng file: %w", path, err)
		}
		return ng, ng.LinkType(), nil
	}
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: not a readable pcap or pcapng file: %w", path, err)
	}
	return pr, pr.LinkType(), nil
}

// packetReader is the bit of pcapgo's readers Wireblast uses. The zero-copy
// variant returns a slice into the reader's own buffer, valid only until the
// next call; Load copies every frame into its contiguous store immediately, so
// nothing is retained, and a multi-gigabyte capture does not churn a second
// capture's worth of per-packet garbage through the heap.
type packetReader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// Len is how many frames the capture holds.
func (f *File) Len() int { return len(f.recs) }

// Frame returns the i-th frame and the gap the capture recorded before it. The
// returned slice aliases the backing store and must not be modified.
func (f *File) Frame(i int) ([]byte, time.Duration) {
	r := f.recs[i]
	return f.data[r.off : r.off+uint64(r.len)], r.gap
}

// MaxLen is the largest frame in the capture, in bytes.
func (f *File) MaxLen() int { return f.maxLen }

// MinLen is the smallest frame in the capture, in bytes.
func (f *File) MinLen() int { return f.minLen }

// MeanLen is the mean frame size, used as the rate limiter's estimate.
func (f *File) MeanLen() int { return f.meanLen }

// Span is the wall-clock duration the capture covers.
func (f *File) Span() time.Duration { return f.span }

// Truncated is how many frames were cut short by the capture's snaplen. Those
// replay as the bytes that were actually captured, which is shorter than what
// the original host sent.
func (f *File) Truncated() int { return f.truncated }

// Bytes is the total size of the loaded frames.
func (f *File) Bytes() int { return len(f.data) }

// Describe summarises the capture for the review screen and the dashboard.
func (f *File) Describe() string {
	s := fmt.Sprintf("%s: %d packets, %d-%d bytes (mean %d)",
		f.path, len(f.recs), f.minLen, f.maxLen, f.meanLen)
	if f.span > 0 {
		s += fmt.Sprintf(", spanning %s", f.span.Round(time.Millisecond))
	}
	if f.truncated > 0 {
		s += fmt.Sprintf(", %d truncated by snaplen", f.truncated)
	}
	return s
}

// Warnings lists things about the capture the user should know before
// replaying it.
func (f *File) Warnings() []string {
	var out []string
	if f.truncated > 0 {
		out = append(out, fmt.Sprintf(
			"%d of %d packets were truncated by the capture's snapshot length. They will be "+
				"replayed at their captured size, which is shorter than the original packet.",
			f.truncated, len(f.recs)))
	}
	if f.skipped > 0 {
		out = append(out, fmt.Sprintf(
			"the capture ends with %d incomplete record(s), which were skipped.", f.skipped))
	}
	return out
}
