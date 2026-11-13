package syslog

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

const (
	// DefaultMaxFrameSize caps one syslog message read from a stream
	// connection. Anything beyond it is dropped, so a sender that never
	// frames its messages can't make the server buffer without limit.
	DefaultMaxFrameSize = 1 << 20

	// An RFC 6587 MSG-LEN longer than this can't be a real length; even
	// 8 digits is far beyond any cap we'd set.
	maxOctetCountDigits = 8
)

// frameReader splits a TCP syslog stream into messages, one frame at a time,
// following RFC 6587:
//
//   - Octet counting (section 3.4.1): "MSG-LEN SP SYSLOG-MSG". Detected when a
//     frame starts with digits, a space and '<'. Exactly MSG-LEN bytes are read.
//   - Non-transparent framing (section 3.4.2): the message ends at LF or NUL.
//     Detected for every other frame start. A trailing CR is removed.
//
// Senders differ, even within one integration, so the framing is detected per
// frame rather than configured. Whitespace and NULs between frames are skipped,
// which handles senders that put a newline after an octet-counted frame.
type frameReader struct {
	r   *bufio.Reader
	max int
	// streak counts octet-counted frames in a row (capped at 2). Two in a
	// row settle the connection as octet-counted: from then on, a frame
	// start that isn't a length means we lost sync (the sender miscounted),
	// so we skip to the next length instead of reading to a newline the
	// sender may never send. One frame isn't enough: a line on a newline
	// connection can look like "123 <...".
	streak int
	// logf reports dropped or skipped data. It may be nil.
	logf func(format string, args ...any)
	// info counts dropped and skipped data and records the framing. It may
	// be nil.
	info *ConnInfo
	// scratch accumulates a non-transparent frame across buffer refills,
	// so a long message is copied once instead of regrown.
	scratch []byte
}

func newFrameReader(r *bufio.Reader, max int) *frameReader {
	if max <= 0 {
		max = DefaultMaxFrameSize
	}
	return &frameReader{r: r, max: max}
}

func (f *frameReader) log(format string, args ...any) {
	if f.logf != nil {
		f.logf(format, args...)
	}
}

// next returns the next message with its framing removed. It can return a
// message together with an error (for example the last unterminated message
// before EOF); callers should use the message and then stop on the error. An
// empty message with a nil error means a frame was dropped; call next again.
func (f *frameReader) next() ([]byte, error) {
	// Skip whitespace and NULs between frames.
	for {
		b, err := f.r.Peek(1)
		if err != nil {
			return nil, err
		}
		if !isFrameSpace(b[0]) {
			break
		}
		_, _ = f.r.Discard(1)
	}

	if n, hdr, ok := f.peekOctetCount(); ok {
		if n > f.max {
			// A length this big is usually the leftover digits of a
			// miscounted frame glued onto the real length ("21" + "297 <").
			// Use a shorter suffix of the digits if it lands exactly on the
			// next frame.
			if skip, sn, ok := f.suffixCount(hdr - 1); ok {
				f.log("Skipped unframed data on octet-counted connection, skipped_bytes=%d", skip)
				f.info.dropped(skip, 0)
				_, _ = f.r.Discard(skip)
				hdr -= skip
				n = sn
			} else if f.streak >= 1 {
				// After an octet-counted frame, nothing verifies a shorter
				// length. Trusting this one would discard n bytes of what
				// are probably good frames (a miscounted first frame's
				// digits glued onto the second's length), so drop the
				// header and resync on the next call.
				f.log("Skipped implausible octet count on octet-counted connection, length=%d, max_bytes=%d", n, f.max)
				f.info.dropped(hdr, 0)
				_, _ = f.r.Discard(hdr)
				return nil, nil
			}
			// Otherwise (the first frame, where nothing can have been
			// miscounted yet) it's an oversized frame: readCounted drops it.
		}
		if f.streak < 2 {
			f.streak++
		}
		_, _ = f.r.Discard(hdr)
		f.info.setFraming(FramingOctet)
		return f.readCounted(n)
	}

	if f.counted() {
		// Not a frame start on an octet-counted connection: we lost sync.
		// Skip to the next octet count, then read it on the next call.
		// Never stop at a bare '<' (it may be inside the leftover text),
		// because reading to a newline would wait forever on a sender like
		// FortiGate that never sends one.
		found, err := f.resync()
		if err != nil {
			return nil, err
		}
		if found {
			return nil, nil
		}
		// No octet count within a frame's worth of data: treat the
		// connection as non-transparent from here on.
	}
	if f.streak == 1 {
		return f.recoverAfterCounted()
	}
	f.streak = 0
	return f.readToTrailer()
}

// recoverAfterCounted handles a frame that doesn't start with an octet count
// right after one that did: usually the leftover of a miscounted first
// frame. Reading to a trailer, as for non-transparent framing, waited until
// the idle timeout on a sender that never sends one (FortiGate), losing
// everything it sent meanwhile. Instead it scans forward and stops at
// whichever comes first:
//   - an octet count: the leftover is dropped, and the next call reads the
//     frame;
//   - an LF or NUL trailer: the bytes were a line after all (a
//     non-transparent sender whose first line looked octet-counted). It's
//     delivered, as before, and the connection reads on as non-transparent.
func (f *frameReader) recoverAfterCounted() ([]byte, error) {
	msg := f.scratch[:0]
	defer func() {
		if cap(msg) <= 64<<10 {
			f.scratch = msg[:0]
		}
	}()
	for len(msg) < f.max {
		if _, _, ok := f.peekOctetCount(); ok {
			if len(msg) > 0 {
				f.log("Skipped unframed data on octet-counted connection, skipped_bytes=%d", len(msg))
				f.info.dropped(len(msg), 0)
			}
			return nil, nil
		}
		c, err := f.r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(msg) > 0 {
				f.streak = 0
				f.info.setFraming(FramingEOF)
				return f.finishTrailer(msg, 0), err
			}
			if len(msg) > 0 {
				f.info.dropped(len(msg), 1)
			}
			return nil, err
		}
		if c == '\n' || (c == 0 && f.nulEndsFrame()) {
			f.streak = 0
			if c == 0 {
				f.info.setFraming(FramingNUL)
			} else {
				f.info.setFraming(FramingLF)
			}
			return f.finishTrailer(msg, 0), nil
		}
		msg = append(msg, c)
	}
	// A frame's worth with neither: drop it and read on as non-transparent.
	f.log("Skipped unframed data on octet-counted connection, skipped_bytes=%d", len(msg))
	f.info.dropped(len(msg), 0)
	f.streak = 0
	return nil, nil
}

// nulEndsFrame reports whether a NUL just read ends a frame: when the next
// byte starts another (or nothing more is buffered yet), as in indexTrailer.
func (f *frameReader) nulEndsFrame() bool {
	if f.r.Buffered() == 0 {
		return true
	}
	b, err := f.r.Peek(1)
	if err != nil {
		return true
	}
	switch b[0] {
	case '<', '\r', '\n', 0:
		return true
	}
	return false
}

// counted reports whether the connection has settled on octet counting.
func (f *frameReader) counted() bool {
	return f.streak >= 2
}

// suffixCount looks for a shorter suffix of the digits digits at the reader
// position that is a length ending exactly where the next frame starts,
// within what's already buffered. It returns how many leading digits to skip
// and the length.
func (f *frameReader) suffixCount(digits int) (skip, n int, ok bool) {
	b, err := f.r.Peek(f.r.Buffered())
	if err != nil || len(b) <= digits {
		return 0, 0, false
	}
	for skip = 1; skip < digits; skip++ {
		if b[skip] == '0' {
			continue // MSG-LEN has no leading zero
		}
		n = 0
		for _, c := range b[skip:digits] {
			n = n*10 + int(c-'0')
		}
		if n > f.max {
			continue
		}
		if end := digits + 1 + n; end < len(b) && isFrameStart(b[end:]) {
			return skip, n, true
		}
	}
	return 0, 0, false
}

// isFrameStart reports whether b starts (after any whitespace or NULs) with
// "MSG-LEN SP <". It needs the header to be in b.
func isFrameStart(b []byte) bool {
	i := 0
	for i < len(b) && isFrameSpace(b[i]) {
		i++
	}
	j := i
	for j < len(b) && j-i < maxOctetCountDigits && b[j] >= '0' && b[j] <= '9' {
		j++
	}
	return j > i && b[i] != '0' && j+1 < len(b) && b[j] == ' ' && b[j+1] == '<'
}

// peekOctetCount reports whether the reader is at "MSG-LEN SP <". It returns
// the length and the size of the "MSG-LEN SP" header. It peeks one byte at a
// time, so it never waits for more data than the header needs.
func (f *frameReader) peekOctetCount() (n int, hdr int, ok bool) {
	b, err := f.r.Peek(1)
	if err != nil || b[0] < '1' || b[0] > '9' {
		return 0, 0, false
	}
	i := 1
	for {
		b, err = f.r.Peek(i + 1)
		if err != nil {
			return 0, 0, false
		}
		c := b[i]
		if c >= '0' && c <= '9' {
			i++
			if i > maxOctetCountDigits {
				return 0, 0, false
			}
			continue
		}
		if c != ' ' {
			return 0, 0, false
		}
		break
	}
	// The message itself must start with a priority header.
	b, err = f.r.Peek(i + 2)
	if err != nil || b[i+1] != '<' {
		return 0, 0, false
	}
	for _, c := range b[:i] {
		n = n*10 + int(c-'0')
	}
	return n, i + 1, true
}

// readCounted reads an octet-counted message of n bytes.
func (f *frameReader) readCounted(n int) ([]byte, error) {
	if n > f.max {
		// Drop it without buffering it, and carry on at the next frame.
		f.log("Dropping oversized syslog frame, size_bytes=%d, max_bytes=%d", n, f.max)
		f.info.dropped(n, 1)
		_, err := f.r.Discard(n)
		return nil, err
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(f.r, msg); err != nil {
		// Cut short (closed, reset or timed out mid-frame): it's
		// incomplete, so don't deliver it as a message.
		return nil, err
	}
	// Some senders count a trailing newline (or NUL) as part of the message.
	return bytes.TrimRight(msg, "\r\n\x00"), nil
}

// readToTrailer reads a non-transparent-framed message up to LF or NUL, or
// up to EOF. Bytes beyond the cap are dropped up to the trailer.
func (f *frameReader) readToTrailer() ([]byte, error) {
	msg := f.scratch[:0]
	defer func() {
		// Keep the grown buffer for the next frame, unless it's huge.
		if cap(msg) <= 64<<10 {
			f.scratch = msg[:0]
		}
	}()
	dropped := 0
	for {
		if f.r.Buffered() == 0 {
			if _, err := f.r.Peek(1); err != nil {
				// At EOF the sender closed after its last message, which
				// may have no trailer: deliver it. Any other error (reset,
				// timeout, Kill) cut the message short: drop it.
				if errors.Is(err, io.EOF) {
					if len(msg) > 0 {
						f.info.setFraming(FramingEOF)
					}
					return f.finishTrailer(msg, dropped), err
				}
				// Cut off mid-message: count what's lost.
				if len(msg)+dropped > 0 {
					f.info.dropped(len(msg)+dropped, 1)
				}
				return nil, err
			}
		}
		chunk, _ := f.r.Peek(f.r.Buffered())
		end := indexTrailer(chunk)
		body := chunk
		if end >= 0 {
			body = chunk[:end]
		}
		if room := f.max - len(msg); len(body) > room {
			dropped += len(body) - room
			body = body[:room]
		}
		msg = append(msg, body...)
		if end >= 0 {
			if chunk[end] == 0 {
				f.info.setFraming(FramingNUL)
			} else {
				f.info.setFraming(FramingLF)
			}
			_, _ = f.r.Discard(end + 1)
			return f.finishTrailer(msg, dropped), nil
		}
		_, _ = f.r.Discard(len(chunk))
	}
}

// finishTrailer returns a copy of msg (which aliases the scratch buffer)
// without a trailing CR.
func (f *frameReader) finishTrailer(msg []byte, dropped int) []byte {
	if dropped > 0 {
		f.log("Truncated oversized syslog message, max_bytes=%d, dropped_bytes=%d",
			f.max, dropped)
		f.info.truncated(dropped)
	}
	if n := len(msg); n > 0 && msg[n-1] == '\r' {
		msg = msg[:n-1]
	}
	if len(msg) == 0 {
		return nil
	}
	return bytes.Clone(msg)
}

// resync skips bytes until the reader is at a valid octet count, and
// reports whether it found one. It gives up after a frame's worth of bytes.
func (f *frameReader) resync() (bool, error) {
	skipped := 0
	defer func() {
		if skipped > 0 {
			f.log("Skipped unframed data on octet-counted connection, skipped_bytes=%d", skipped)
			f.info.dropped(skipped, 0)
		}
	}()
	for skipped < f.max {
		if _, _, ok := f.peekOctetCount(); ok {
			return true, nil
		}
		if _, err := f.r.Discard(1); err != nil {
			return false, err
		}
		skipped++
	}
	return false, nil
}

func isFrameSpace(c byte) bool {
	return c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == 0
}

// indexTrailer returns the index of the first trailer in b, or -1. A trailer
// is an LF, or a NUL that ends a message: one followed by '<', CR, LF,
// another NUL, or nothing yet (Sophos ends each message with a NUL). A NUL
// followed by other text is inside a message and is kept.
func indexTrailer(b []byte) int {
	lf := bytes.IndexByte(b, '\n')
	limit := len(b)
	if lf >= 0 {
		limit = lf
	}
	for i := 0; i < limit; {
		j := bytes.IndexByte(b[i:limit], 0)
		if j < 0 {
			break
		}
		j += i
		if j+1 >= len(b) {
			return j
		}
		switch b[j+1] {
		case '<', '\r', '\n', 0:
			return j
		}
		i = j + 1
	}
	return lf
}
