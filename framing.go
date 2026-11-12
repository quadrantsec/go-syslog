package syslog

import (
	"bufio"
	"bytes"
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
	// counted is true when the previous frame used octet counting. An
	// unrecognized frame start on such a connection means we lost sync
	// (for example the sender miscounted), so we skip to the next frame
	// instead of reading to a newline the sender may never send.
	counted bool
	// logf reports dropped or skipped data. It may be nil.
	logf func(format string, args ...any)
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
		_, _ = f.r.Discard(hdr)
		f.counted = true
		return f.readCounted(n)
	}

	b, _ := f.r.Peek(1)
	if b[0] != '<' && f.counted {
		if err := f.resync(); err != nil {
			return nil, err
		}
		// resync stops at a '<' or a valid octet count.
		if n, hdr, ok := f.peekOctetCount(); ok {
			_, _ = f.r.Discard(hdr)
			return f.readCounted(n)
		}
	}
	f.counted = false
	return f.readToTrailer()
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
		discarded, err := f.r.Discard(n)
		f.log("Dropped oversized syslog frame, size_bytes=%d, max_bytes=%d, discarded_bytes=%d",
			n, f.max, discarded)
		return nil, err
	}
	msg := make([]byte, n)
	read, err := io.ReadFull(f.r, msg)
	// Some senders count a trailing newline (or NUL) as part of the message.
	return bytes.TrimRight(msg[:read], "\r\n\x00"), err
}

// readToTrailer reads a non-transparent-framed message up to LF or NUL, or
// up to EOF. Bytes beyond the cap are dropped up to the trailer.
func (f *frameReader) readToTrailer() ([]byte, error) {
	var msg []byte
	dropped := 0
	for {
		if f.r.Buffered() == 0 {
			if _, err := f.r.Peek(1); err != nil {
				return f.finishTrailer(msg, dropped), err
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
			_, _ = f.r.Discard(end + 1)
			return f.finishTrailer(msg, dropped), nil
		}
		_, _ = f.r.Discard(len(chunk))
	}
}

func (f *frameReader) finishTrailer(msg []byte, dropped int) []byte {
	if dropped > 0 {
		f.log("Truncated oversized syslog message, max_bytes=%d, dropped_bytes=%d",
			f.max, dropped)
	}
	if n := len(msg); n > 0 && msg[n-1] == '\r' {
		msg = msg[:n-1]
	}
	return msg
}

// resync skips bytes until the reader is at a '<' or at a valid octet count.
func (f *frameReader) resync() error {
	skipped := 0
	defer func() {
		if skipped > 0 {
			f.log("Skipped unframed data on octet-counted connection, skipped_bytes=%d", skipped)
		}
	}()
	for {
		b, err := f.r.Peek(1)
		if err != nil {
			return err
		}
		if b[0] == '<' {
			return nil
		}
		if _, _, ok := f.peekOctetCount(); ok {
			return nil
		}
		_, _ = f.r.Discard(1)
		skipped++
	}
}

func isFrameSpace(c byte) bool {
	return c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == 0
}

// indexTrailer returns the index of the first LF or NUL in b, or -1.
func indexTrailer(b []byte) int {
	lf := bytes.IndexByte(b, '\n')
	nul := bytes.IndexByte(b, 0)
	if lf < 0 || (nul >= 0 && nul < lf) {
		return nul
	}
	return lf
}
