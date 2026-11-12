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
func TestFramingSeparatorsBetweenOctetFrames(t *testing.T) {
	checkFrames(t,
		"\r\n \x00"+octet(sampleFortiGate1)+"\n\n"+octet(sampleLinux)+"\x00\n"+octet(sampleFortiGate2),
		sampleFortiGate1, sampleLinux, sampleFortiGate2)
}

func TestFramingSeparatorsBetweenNonTransparentFrames(t *testing.T) {
	checkFrames(t,
		"\r\n \x00"+sampleLinux+"\n\n"+sampleFTD+"\x00\n"+sampleSophos+"\x00",
		sampleLinux, sampleFTD, sampleSophos)
}

// Once a connection has sent two octet frames in a row, it's read as
// octet-counted: a frame that doesn't start with a length is treated as
// lost sync and skipped. No sender mixes framings on one connection, and stopping at a
// '<' would wait forever for a newline FortiGate never sends.
func TestFramingOctetConnectionStaysOctet(t *testing.T) {
	checkFrames(t,
		octet(sampleFortiGate1)+octet(sampleFortiGate1)+sampleLinux+"\n"+octet(sampleFortiGate2),
		sampleFortiGate1, sampleFortiGate1, sampleFortiGate2)
}

// A sender that undercounts: the leftover bytes are skipped and the next
// octet-counted frame is read normally, instead of reading to a newline a
// FortiGate never sends.
func TestFramingResyncAfterMiscount(t *testing.T) {
	msg := `<189>1 2026-10-27T14:03:13-05:00 FGT-EDGE-01 - - - - logid="0000000020" action="close" msg="done"`
	bad := fmt.Sprintf("%d %s", len(msg)-7, msg)
	checkFrames(t,
		octet(sampleFortiGate1)+octet(sampleFortiGate2)+bad+octet(sampleFortiGate2)+octet(sampleFortiGate1),
		sampleFortiGate1, sampleFortiGate2, msg[:len(msg)-7], sampleFortiGate2, sampleFortiGate1)
}

// The leftover contains a '<'. Resync must not stop there and read to a
// newline: FortiGate never sends one, so nothing more would be delivered.
func TestFramingResyncSkipsBareBracket(t *testing.T) {
	msg := `<189>1 2026-10-27T14:03:14-05:00 FGT-EDGE-01 - - - - logid="0102043008" user="<admin>" action="login"`
	cut := strings.Index(msg, `"<admin>`)
	bad := fmt.Sprintf("%d %s", cut, msg)
	input := octet(sampleFortiGate1) + octet(sampleFortiGate2) + bad
	want := []string{sampleFortiGate1, sampleFortiGate2, msg[:cut]}
	for range 50 {
		input += octet(sampleFortiGate2)
		want = append(want, sampleFortiGate2)
	}
	checkFrames(t, input, want...)
}

// The leftover ends in digits that run into the next length and make it
// absurd ("8443" + "297 <"). The real length is recovered from the digits
// instead of discarding megabytes of good frames.
func TestFramingResyncGluedDigitsOverCap(t *testing.T) {
	msg := `<189>1 2026-10-27T14:03:15-05:00 FGT-EDGE-01 - - - - logid="0000000013" sentbyte=8443`
	bad := fmt.Sprintf("%d %s", len(msg)-4, msg) // leaves "8443"
	got, err := readAll(t, strings.NewReader(bad+octet(sampleFortiGate2)+octet(sampleFortiGate1)), 1<<20)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
	want := []string{msg[:len(msg)-4], sampleFortiGate2, sampleFortiGate1}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// A frame cut short by the connection closing is incomplete: it isn't
// delivered as a message.
func TestFramingPartialOctetFrame(t *testing.T) {
	got, err := readAll(t, strings.NewReader(octet(sampleFortiGate1)[:40]), 0)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no message, got %q", got)
	}
}

// errReader returns its data, then err.
type errReader struct {
	data string
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.data == "" {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

var errTimeout = errors.New("i/o timeout")

// A message cut short by a timeout, reset or Kill isn't delivered, for
// either framing. At EOF the last unterminated message still is.
func TestFramingPartialOnErrorDropped(t *testing.T) {
	for name, input := range map[string]string{
		"octet":           octet(sampleFortiGate1) + octet(sampleFortiGate2)[:40],
		"non-transparent": sampleLinux + "\n" + sampleFTD[:40],
	} {
		got, err := readAll(t, &errReader{input, errTimeout}, 0)
		if !errors.Is(err, errTimeout) {
			t.Errorf("%s: want the timeout, got %v", name, err)
		}
		if len(got) != 1 {
			t.Errorf("%s: want only the complete message, got %d: %q", name, len(got), got)
		}
	}
}

// A line on a newline connection that looks like "5 <..." is read as one
// octet frame, but doesn't switch the connection to octet counting: the
// lines after it are still split on LF.
func TestFramingFalseOctetHeaderOnNewlineConnection(t *testing.T) {
	input := "<13>first\n" + "5 <x>yz\n"
	want := []string{"<13>first", "<x>yz"}
	for range 20 {
		input += sampleLinux + "\n"
		want = append(want, sampleLinux)
	}
	checkFrames(t, input, want...)
}

// An over-cap length on an octet-counted connection that no shorter suffix
// verifies (the next frame hasn't arrived yet) is skipped with a resync,
// not trusted: trusting it discarded megabytes of good frames.
func TestFramingOverCapUnverifiedResyncs(t *testing.T) {
	msg := `<189>1 2026-10-27T14:03:15-05:00 FGT-EDGE-01 - - - - logid="0000000013" sentbyte=13107`
	glued := fmt.Sprintf("%d %s", len(msg)-5, msg) // leaves "13107" glued onto the next length
	next := octet(sampleFortiGate2)
	first := octet(sampleFortiGate1) + octet(sampleFortiGate1) + glued + next
	var later strings.Builder
	for range 400 {
		later.WriteString(octet(sampleFortiGate1))
	}
	// Separate reads, so the frame after the glued length isn't buffered
	// when the length is checked.
	r := io.MultiReader(strings.NewReader(first), strings.NewReader(later.String()))
	got, err := readAll(t, r, 1<<20)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
	// The glued frame is lost; everything after it is delivered.
	if len(got) < 403 {
		t.Fatalf("delivered %d messages, want at least 403", len(got))
	}
	for i, m := range got[len(got)-400:] {
		if m != sampleFortiGate1 {
			t.Fatalf("message %d after the resync is %q", i, m)
		}
	}
}

// A NUL inside a line is content, not a trailer; Sophos's NUL after each
// message still is.
func TestFramingEmbeddedNUL(t *testing.T) {
	checkFrames(t,
		"<13>abc\x00def\n"+sampleSophos+"\x00"+sampleSophos+"\x00",
		"<13>abc\x00def", sampleSophos, sampleSophos)
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
		"":              -1,
		"abc":           -1,
		"ab\ncd\x00":    2,
		"ab\x00cd\n":    5,
		"ab\x00<1>":     2,
		"ab\x00":        2,
		"ab\x00\r\n":    2,
		"ab\x00\x00":    2,
		"\n":            0,
		"\x00":          0,
		"a\x00b\x00<1>": 3,
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
