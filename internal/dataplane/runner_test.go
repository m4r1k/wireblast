package dataplane

import (
	"os"
	"testing"
)

// frameSizeFor picks the UMEM frame size. Two things matter. A frame may never
// exceed a page, because an aligned-chunk UMEM larger than PAGE_SIZE makes
// XDP_UMEM_REG fail with a bare EINVAL. So jumbo traffic gets a page and
// chains, it does not get a bigger frame. And AWS ENA's zero-copy bind needs
// page-sized frames, so a standard frame is floored to 4096 there while every
// other driver keeps the smaller 2048.
func TestFrameSizeFor(t *testing.T) {
	tests := []struct {
		driver   string
		maxFrame int
		want     int
	}{
		{"ena", 1518, 4096},   // a standard frame is floored to a page on ena
		{"ixgbe", 1518, 2048}, // other drivers keep the smaller frame
		{"", 1518, 2048},      // unknown driver behaves like non-ena
		{"ena", 3018, 4096},   // already 4096, the floor is a no-op
		{"ena", 64, 4096},     // a tiny frame still gets a page on ena

		// Above 2048 every driver takes a page, and stops there. These are the
		// sizes that used to ask for 8192 or 16384 and get EINVAL.
		{"ixgbe", 2049, 4096},
		{"ixgbe", 4097, 4096},
		{"ena", 9018, 4096},
		{"mlx5_core", 9018, 4096},
		{"mlx5_core", 16384, 4096},
	}
	for _, tt := range tests {
		got := frameSizeFor(tt.maxFrame, tt.driver)
		if got != tt.want {
			t.Errorf("frameSizeFor(%d, %q) = %d, want %d", tt.maxFrame, tt.driver, got, tt.want)
		}
		if page := os.Getpagesize(); got > page {
			t.Errorf("frameSizeFor(%d, %q) = %d, above the %d-byte page the kernel allows",
				tt.maxFrame, tt.driver, got, page)
		}
	}
}

// Chaining is what carries a packet that no longer fits one frame, so it must
// turn on exactly when that happens and stay off otherwise: it costs zero-copy
// on drivers that will not accept an XDP_USE_SG bind.
func TestMultiBufferFor(t *testing.T) {
	tests := []struct {
		maxFrame  int
		frameSize int
		want      bool
	}{
		{60, 2048, false},   // a 64-byte frame
		{1514, 2048, false}, // a standard frame
		{2048, 2048, false}, // exactly a frame still fits
		{2049, 4096, false}, // ...and gets a bigger frame rather than chaining
		{4096, 4096, false}, // exactly a page fits
		{4097, 4096, true},  // one byte over is where chaining starts
		{9014, 4096, true},  // a jumbo frame
	}
	for _, tt := range tests {
		if got := multiBufferFor(tt.maxFrame, tt.frameSize); got != tt.want {
			t.Errorf("multiBufferFor(%d, %d) = %v, want %v",
				tt.maxFrame, tt.frameSize, got, tt.want)
		}
	}
}

// framesPerPacket feeds preflight's chain-length check, so the boundaries have
// to be exact rather than approximately right.
func TestFramesPerPacket(t *testing.T) {
	tests := []struct {
		maxFrame  int
		frameSize int
		want      int
	}{
		{0, 4096, 1},    // degenerate input never reports zero frames
		{60, 4096, 1},   //
		{4096, 4096, 1}, // exactly one frame
		{4097, 4096, 2}, // one byte over needs a second
		{9014, 4096, 3}, // a jumbo frame spans three
		{8192, 4096, 2},
	}
	for _, tt := range tests {
		if got := framesPerPacket(tt.maxFrame, tt.frameSize); got != tt.want {
			t.Errorf("framesPerPacket(%d, %d) = %d, want %d",
				tt.maxFrame, tt.frameSize, got, tt.want)
		}
	}
}
