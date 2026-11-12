package syslog

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
)

// Synthetic samples shaped like what each kind of sender puts on the wire
// (measured for QIS-833). Hosts and addresses are made up (RFC 5737).
const (
	// RFC 5424 with key=value body, as FortiGate sends in reliable mode.
	sampleFortiGate1 = `<189>1 2026-10-27T14:03:11-05:00 FGT-EDGE-01 - - - - logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.0.2.10 srcport=51234 dstip=198.51.100.7 dstport=9000 proto=6 action="close" sentpkt=3 rcvdpkt=21`
	sampleFortiGate2 = `<189>1 2026-10-27T14:03:12-05:00 FGT-EDGE-01 - - - - logid="0001000014" type="traffic" subtype="local" level="notice" srcip=192.0.2.11 dstip=203.0.113.53 dstport=53 proto=17 action="accept" qclass="IN" srcserver=0`
	// RFC 5424 with a JSON body, as Barracuda Email Gateway Defense sends.
	sampleBarracuda = `<134>1 2026-11-09T15:00:00Z ess.example.net - - - - {"account_id":"ESS00000","domain_id":"1","recipient":"user@example.com","action":"allowed"}`
	// RFC 3164, as rsyslog sends.
	sampleLinux = `<38>Nov  9 15:00:01 web01 sshd[1234]: Accepted publickey for root from 192.0.2.5 port 50000 ssh2`
	// Sophos XG: key=value body, each message ends in a NUL.
	sampleSophos = `<30>device_name="SFW" timestamp="2026-11-09T10:00:00+0000" log_type="Firewall" log_component="Firewall Rule" src_ip="192.0.2.20" dst_ip="198.51.100.20" fw_rule_id="5"`
	// Cisco FTD, newline framed.
	sampleFTD = `<166>Nov 10 2026 10:00:00 ftd01 : %FTD-6-430003: Protocol: TCP, SrcIP: 192.0.2.30, DstIP: 198.51.100.30, SrcPort: 51000, DstPort: 443`
)

func octet(msg string) string {
	return fmt.Sprintf("%d %s", len(msg), msg)
}

// readAll runs a frameReader over r and returns every message and the final
// error.
func readAll(t *testing.T, r io.Reader, max int) ([]string, error) {
	t.Helper()
	fr := newFrameReader(bufio.NewReader(r), max)
	var msgs []string
	for range 1000 {
		msg, err := fr.next()
		if len(msg) > 0 {
			msgs = append(msgs, string(msg))
		}
		if err != nil {
			return msgs, err
		}
	}
	t.Fatal("frame reader did not reach EOF")
	return nil, nil
}

func checkFrames(t *testing.T, input string, want ...string) {
	t.Helper()
	got, err := readAll(t, strings.NewReader(input), 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("want %d messages, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("message %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

// FortiGate: length prefix, no newline. 2.5.3 stored "rcvdpkt=21<next length> ".
func TestFramingOctetCountedNoTrailer(t *testing.T) {
	checkFrames(t,
		octet(sampleFortiGate1)+octet(sampleFortiGate2)+octet(sampleFortiGate1),
		sampleFortiGate1, sampleFortiGate2, sampleFortiGate1)
}

// Barracuda, paloalto, freebsd, vcenter, some linux: length prefix and a
// newline after each message. 2.5.3 stored "\n<next length> " at the end.
func TestFramingOctetCountedNewlineAfter(t *testing.T) {
	checkFrames(t,
		octet(sampleBarracuda)+"\n"+octet(sampleLinux)+"\n",
		sampleBarracuda, sampleLinux)
}

// Some senders count the newline as part of the message.
func TestFramingOctetCountedNewlineInside(t *testing.T) {
	checkFrames(t,
		octet(sampleBarracuda+"\n")+octet(sampleLinux+"\r\n"),
		sampleBarracuda, sampleLinux)
}

// forescout, some linux, cisco_ftd: newline only.
func TestFramingNewline(t *testing.T) {
	checkFrames(t,
		sampleLinux+"\n"+sampleFTD+"\r\n"+sampleLinux+"\n",
		sampleLinux, sampleFTD, sampleLinux)
}

// Sophos: a NUL after each message. 2.5.3 stored the NUL.
func TestFramingNUL(t *testing.T) {
	checkFrames(t,
		sampleSophos+"\x00"+sampleSophos+"\x00",
		sampleSophos, sampleSophos)
}

// 2.5.3 split wherever "<digits>" appeared, even inside a message.
func TestFramingPriorityLookalikeInsideMessage(t *testing.T) {
	msg := `<14>Nov  9 15:00:01 mail01 postfix/smtpd[99]: NOQUEUE: reject: from=<123> to=<4>`
	checkFrames(t, msg+"\n"+octet(msg), msg, msg)
}

// The last message is delivered even without a trailer, once the peer closes.
func TestFramingLastMessageWithoutTrailer(t *testing.T) {
	checkFrames(t, sampleLinux+"\n"+sampleFTD, sampleLinux, sampleFTD)
}

// A newline-framed sender that sends a multi-line message: each line is
// kept, not dropped.
func TestFramingContinuationLineKept(t *testing.T) {
	checkFrames(t,
		sampleLinux+"\n\tat com.example.Main(Main.java:10)\n"+sampleFTD+"\n",
		sampleLinux, "at com.example.Main(Main.java:10)", sampleFTD)
}

// Digits and a space that aren't followed by '<' aren't a length.
func TestFramingDigitsWithoutOctetHeader(t *testing.T) {
	checkFrames(t, "2026 is not a length\n"+sampleLinux+"\n",
		"2026 is not a length", sampleLinux)
}

// Whitespace and NULs between frames are skipped.
func TestFramingMixedSeparators(t *testing.T) {
	checkFrames(t,
		"\r\n \x00"+octet(sampleFortiGate1)+"\n\n"+sampleLinux+"\x00\n"+octet(sampleFortiGate2),
		sampleFortiGate1, sampleLinux, sampleFortiGate2)
}

// A sender that undercounts: the leftover bytes are skipped and the next
// octet-counted frame is read normally, instead of reading to a newline a
// FortiGate never sends. (If the leftover ends in digits, they run into the
// next frame's length and no reader can tell; senders count correctly in
// practice, so this only limits the damage.)
func TestFramingResyncAfterMiscount(t *testing.T) {
	msg := `<189>1 2026-10-27T14:03:13-05:00 FGT-EDGE-01 - - - - logid="0000000020" action="close" msg="done"`
	bad := fmt.Sprintf("%d %s", len(msg)-7, msg)
	checkFrames(t,
		bad+octet(sampleFortiGate2)+octet(sampleFortiGate1),
		msg[:len(msg)-7], sampleFortiGate2, sampleFortiGate1)
}

// A connection that closes mid-frame returns what arrived and the error.
func TestFramingPartialOctetFrame(t *testing.T) {
	got, err := readAll(t, strings.NewReader(octet(sampleFortiGate1)[:40]), 0)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
	if len(got) != 1 || !strings.HasPrefix(sampleFortiGate1, got[0]) {
		t.Fatalf("want the partial frame, got %q", got)
	}
}

type repeatReader byte

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// allocated returns how many bytes fn allocates.
func allocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// An octet count above the cap is dropped without being buffered, and the
// next frame is read normally.
func TestFramingOversizedOctetFrame(t *testing.T) {
	const max = 1024
	const size = 16 << 20
	var got []string
	var err error
	alloc := allocated(func() {
		r := io.MultiReader(
			strings.NewReader(fmt.Sprintf("%d <13>", size)),
			io.LimitReader(repeatReader('a'), int64(size-len("<13>"))),
			strings.NewReader(octet(sampleFortiGate1)),
		)
		got, err = readAll(t, r, max)
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
	if len(got) != 1 || got[0] != sampleFortiGate1 {
		t.Fatalf("want only the frame after the oversized one, got %d messages", len(got))
	}
	if alloc > 1<<20 {
		t.Errorf("allocated %d bytes to skip a %d byte frame", alloc, size)
	}
}

// A sender that never sends a newline is truncated at the cap; memory stays
// bounded, and the stream recovers at the next trailer.
func TestFramingOversizedUnterminated(t *testing.T) {
	const max = 1024
	const size = 16 << 20
	var got []string
	var err error
	alloc := allocated(func() {
		r := io.MultiReader(
			strings.NewReader("<13>"),
			io.LimitReader(repeatReader('a'), size),
			strings.NewReader("\n"+sampleLinux+"\n"),
		)
		got, err = readAll(t, r, max)
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 messages, got %d", len(got))
	}
	if len(got[0]) != max || !strings.HasPrefix(got[0], "<13>aaa") {
		t.Errorf("want the first %d bytes, got %d bytes starting %q", max, len(got[0]), got[0][:10])
	}
	if got[1] != sampleLinux {
		t.Errorf("want %q, got %q", sampleLinux, got[1])
	}
	if alloc > 1<<20 {
		t.Errorf("allocated %d bytes for a %d byte unterminated message", alloc, size)
	}
}

func TestIndexTrailer(t *testing.T) {
	for in, want := range map[string]int{
		"":           -1,
		"abc":        -1,
		"ab\ncd\x00": 2,
		"ab\x00cd\n": 2,
		"\n":         0,
		"\x00":       0,
	} {
		if got := indexTrailer([]byte(in)); got != want {
			t.Errorf("indexTrailer(%q) = %d, want %d", in, got, want)
		}
	}
}

func benchmarkFrames(b *testing.B, frame string) {
	stream := []byte(strings.Repeat(frame, 1000))
	b.SetBytes(int64(len(stream)))
	b.ReportAllocs()
	for b.Loop() {
		fr := newFrameReader(bufio.NewReader(bytes.NewReader(stream)), 0)
		for {
			if _, err := fr.next(); err != nil {
				break
			}
		}
	}
}

func BenchmarkFramesOctetCounted(b *testing.B) { benchmarkFrames(b, octet(sampleFortiGate1)) }
func BenchmarkFramesNewline(b *testing.B)      { benchmarkFrames(b, sampleLinux+"\n") }
func BenchmarkFramesLongNewline(b *testing.B) {
	benchmarkFrames(b, "<134>"+strings.Repeat("x", 60000)+"\n")
}
