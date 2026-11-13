package syslog

import (
	"bytes"
	"log"
)

// FirstFrameFilter decides whether a stream connection's opening frames are
// syslog. The server calls it for each frame until one is accepted. Frames
// it rejects are neither parsed nor handed to the Handler; they're counted
// in the connection's ConnInfo (FilteredFrames, FilteredBytes,
// FirstFiltered). Once a frame is accepted the filter isn't called again
// for that connection, so frames later in a stream are never filtered.
//
// It runs on the connection's goroutine, so it must be quick. frame is only
// valid during the call. A filter that panics accepts the frame.
type FirstFrameFilter func(info *ConnInfo, frame []byte) bool

// SetFirstFrameFilter sets the filter for stream connections' opening
// frames (nil, the default, accepts everything). Set it before Boot.
// LooksLikeSyslog is the usual test.
func (s *Server) SetFirstFrameFilter(f FirstFrameFilter) {
	s.firstFrameFilter = f
}

// acceptFrame reports whether a frame read from a connection goes on to the
// parser. Only frames before the connection's first accepted one are
// filtered.
func (s *Server) acceptFrame(info *ConnInfo, msg []byte) bool {
	f := s.firstFrameFilter
	if f == nil || info.frames.Load() > 0 {
		return true
	}
	if callFirstFrameFilter(f, info, msg) {
		return true
	}
	info.filtered(msg)
	return false
}

// callFirstFrameFilter runs the filter, accepting the frame if it panics:
// a bug in the policy must not drop a sender's logs.
func callFirstFrameFilter(f FirstFrameFilter, info *ConnInfo, msg []byte) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in first-frame filter, accepting the frame, remote=%s, error=%v",
				info.Source(), r)
			ok = true
		}
	}()
	return f(info, msg)
}

var utf8BOM = []byte("\xef\xbb\xbf")

// LooksLikeSyslog reports whether a frame starts the way a syslog message
// does:
//
//   - with a PRI, "<0>" to "<191>";
//   - or, for senders that leave the PRI out, with a timestamp: RFC 3339
//     ("2006-01-02T15:04:05Z", any fraction, an offset or none), or BSD
//     ("Jan _2 15:04:05", with or without a year after the day);
//   - or with "<-1>" and such a timestamp, which Cisco FTD sends for some
//     messages;
//   - or with a CEF ("CEF:0|") or LEEF ("LEEF:1.0|") header, which some
//     appliances send without a syslog header.
//
// A leading UTF-8 BOM is ignored. Internet scanners' probes (HTTP, RTSP,
// SMTP and FTP commands, TLS, SMB, RPC, DNS, XML, other binary) start with
// none of these, so a connection whose first frames fail this test is
// almost certainly not a syslog sender.
func LooksLikeSyslog(frame []byte) bool {
	b := bytes.TrimPrefix(frame, utf8BOM)
	if len(b) == 0 {
		return false
	}
	if b[0] == '<' {
		if validPRI(b) {
			return true
		}
		if rest, ok := bytes.CutPrefix(b, []byte("<-1>")); ok {
			return startsWithTimestamp(bytes.TrimPrefix(rest, []byte(" ")))
		}
		return false
	}
	return startsWithTimestamp(b) || startsWithCEFOrLEEF(b)
}

// startsWithCEFOrLEEF reports whether b starts with "CEF:<digit>" or
// "LEEF:<digit>", then a version or field separator.
func startsWithCEFOrLEEF(b []byte) bool {
	for _, p := range [][]byte{[]byte("CEF:"), []byte("LEEF:")} {
		if rest, ok := bytes.CutPrefix(b, p); ok {
			return len(rest) >= 2 && isDigit(rest[0]) && (rest[1] == '|' || rest[1] == '.')
		}
	}
	return false
}

// validPRI reports whether b starts with "<N>", N from 0 to 191 in 1 to 3
// digits.
func validPRI(b []byte) bool {
	i, v := 1, 0
	for i < len(b) && i <= 3 && isDigit(b[i]) {
		v = v*10 + int(b[i]-'0')
		i++
	}
	return i > 1 && i < len(b) && b[i] == '>' && v <= 191
}

func startsWithTimestamp(b []byte) bool {
	return startsWithRFC3339(b) || startsWithBSDStamp(b)
}

// startsWithRFC3339 reports whether b starts with
// YYYY-MM-DD[T ]hh:mm:ss[.frac][Z|±hh:mm|±hhmm], followed by the end or a
// byte that can't continue it.
func startsWithRFC3339(b []byte) bool {
	const n = len("2006-01-02T15:04:05")
	if len(b) < n {
		return false
	}
	for i, c := range []byte("dddd-dd-ddTdd:dd:dd") {
		switch c {
		case 'd':
			if !isDigit(b[i]) {
				return false
			}
		case 'T':
			if b[i] != 'T' && b[i] != 't' && b[i] != ' ' {
				return false
			}
		default:
			if b[i] != c {
				return false
			}
		}
	}
	if !inRange(b[5:7], 1, 12) || !inRange(b[8:10], 1, 31) ||
		!inRange(b[11:13], 0, 23) || !inRange(b[14:16], 0, 59) || !inRange(b[17:19], 0, 60) {
		return false
	}
	i := n
	if i < len(b) && b[i] == '.' {
		j := i + 1
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if j == i+1 {
			return false
		}
		i = j
	}
	switch {
	case i < len(b) && (b[i] == 'Z' || b[i] == 'z'):
		i++
	case i < len(b) && (b[i] == '+' || b[i] == '-'):
		switch {
		case i+6 <= len(b) && isDigit(b[i+1]) && isDigit(b[i+2]) && b[i+3] == ':' &&
			isDigit(b[i+4]) && isDigit(b[i+5]):
			i += 6
		case i+5 <= len(b) && isDigit(b[i+1]) && isDigit(b[i+2]) && isDigit(b[i+3]) && isDigit(b[i+4]):
			i += 5
		default:
			return false
		}
	}
	return i == len(b) || !isAlnum(b[i])
}

var months = [][]byte{
	[]byte("Jan"), []byte("Feb"), []byte("Mar"), []byte("Apr"), []byte("May"), []byte("Jun"),
	[]byte("Jul"), []byte("Aug"), []byte("Sep"), []byte("Oct"), []byte("Nov"), []byte("Dec"),
}

// startsWithBSDStamp reports whether b starts with "Mmm d hh:mm:ss" (the
// day space-padded or not) or "Mmm d yyyy hh:mm:ss", followed by the end or
// a byte that can't continue it.
func startsWithBSDStamp(b []byte) bool {
	if len(b) < len("Jan 2 15:04:05") {
		return false
	}
	month := false
	for _, m := range months {
		if bytes.EqualFold(b[:3], m) {
			month = true
			break
		}
	}
	if !month || b[3] != ' ' {
		return false
	}
	i := 4
	if b[i] == ' ' { // "Jan  2"
		i++
	}
	d := i
	for i < len(b) && i-d < 2 && isDigit(b[i]) {
		i++
	}
	if i == d || !inRange(b[d:i], 1, 31) || i >= len(b) || b[i] != ' ' {
		return false
	}
	i++
	// Optional year: "Nov 13 2026 00:00:29"
	if i+5 <= len(b) && isDigit(b[i]) && isDigit(b[i+1]) && isDigit(b[i+2]) && isDigit(b[i+3]) && b[i+4] == ' ' {
		i += 5
	}
	if i+8 > len(b) {
		return false
	}
	t := b[i : i+8]
	if !isDigit(t[0]) || !isDigit(t[1]) || t[2] != ':' || !isDigit(t[3]) || !isDigit(t[4]) ||
		t[5] != ':' || !isDigit(t[6]) || !isDigit(t[7]) ||
		!inRange(t[0:2], 0, 23) || !inRange(t[3:5], 0, 59) || !inRange(t[6:8], 0, 60) {
		return false
	}
	i += 8
	return i == len(b) || !isAlnum(b[i])
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// inRange reports whether the digits in b are a number from lo to hi.
func inRange(b []byte, lo, hi int) bool {
	v := 0
	for _, c := range b {
		if !isDigit(c) {
			return false
		}
		v = v*10 + int(c-'0')
	}
	return len(b) > 0 && v >= lo && v <= hi
}
