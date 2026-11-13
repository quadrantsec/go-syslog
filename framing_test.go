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

// msgAt returns a distinct RFC 5424 FortiGate-style message.
func msgAt(i int) string {
	return fmt.Sprintf(`<189>1 2026-11-13T05:00:%02d-05:00 FGT-EDGE-01 - - - - logid="0000000013" seq=%d action="close"`, i%60, i)
}

// An undercounted first frame on an octet-only sender (no LF, like
// FortiGate) used to send the reader looking for a trailer that never comes:
// nothing more was delivered until the idle timeout.
func TestUndercountedFirstFrameOctetOnly(t *testing.T) {
	first := msgAt(0)
	input := fmt.Sprintf("%d %s", len(first)-7, first)
	for i := 1; i <= 50; i++ {
		input += octet(msgAt(i))
	}
	// The sender then goes quiet until the idle timeout, as FortiGate
	// does between bursts: everything before it must be out by then.
	got, err := readAll(t, &errReader{input, errTimeout}, 0)
	if !errors.Is(err, errTimeout) {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 51 || got[0] != first[:len(first)-7] || got[50] != msgAt(50) {
		t.Fatalf("got %d messages (first %q), want 51", len(got), got[0])
	}
}

// Overcounted by exactly the next frame's header, the leftover starts with
// '<' (the second frame's body): it's dropped, and reading carries on.
func TestOvercountedFirstFrameOctetOnly(t *testing.T) {
	first, second := msgAt(0), msgAt(1)
	hdr := fmt.Sprintf("%d ", len(second))
	input := fmt.Sprintf("%d %s", len(first)+len(hdr), first) + hdr + second
	for i := 2; i <= 50; i++ {
		input += octet(msgAt(i))
	}
	got, err := readAll(t, strings.NewReader(input), 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v", err)
	}
	// The first message carries the second's header; the second is lost.
	if len(got) != 50 || got[len(got)-1] != msgAt(50) {
		t.Fatalf("got %d messages, want 50 (the 2nd lost)", len(got))
	}
}

// A miscounted first frame's digits glued onto the second frame's length make
// a length over the cap. With the frames arriving one per read nothing can
// verify a shorter suffix, and the huge length used to be trusted after one
// frame: every later frame was discarded.
func TestGluedLengthAfterFirstFrameSlowSender(t *testing.T) {
	first := msgAt(0) + " sentbyte=13107"
	chunks := []string{fmt.Sprintf("%d %s", len(first)-5, first)}
	for i := 1; i <= 300; i++ {
		chunks = append(chunks, octet(msgAt(i)))
	}
	got, err := readAll(t, &oneChunkReader{chunks: chunks}, 1<<20)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v", err)
	}
	// Only the frame whose length was glued is lost.
	if len(got) != 300 || got[0] != first[:len(first)-5] || got[1] != msgAt(2) || got[299] != msgAt(300) {
		t.Fatalf("delivered %d of 301, want all but the 2nd", len(got))
	}
}

// A non-transparent sender whose first line happens to look octet-counted
// loses nothing it didn't lose before: the rest of that line is delivered,
// and the following lines are read as lines.
func TestLineSenderFirstLineLooksCounted(t *testing.T) {
	got, err := readAll(t, strings.NewReader("12 <13>hello world\n<13>two\n<13>three\x00<13>four\n"), 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v", err)
	}
	want := []string{"<13>hello wo", "rld", "<13>two", "<13>three", "<13>four"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// oneChunkReader returns one chunk per Read, like a sender that writes one
// frame at a time.
type oneChunkReader struct{ chunks []string }

func (c *oneChunkReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	if c.chunks[0] == "" {
		c.chunks = c.chunks[1:]
	}
	return n, nil
}

// While recovering, an octet count can turn up mid-line on a line sender
// ("3 <b@...", "5.1.1 <user@..."). Reading it as a frame used to settle the
// connection on octet counting, and resync then discarded up to a frame's
// worth at a time, for the rest of the connection.
func TestLineSenderLookalikeInLeftover(t *testing.T) {
	for name, tc := range map[string]struct {
		input, line string
		n           int
	}{
		"first line": {"2 <a@example.com> 3 <b@example.com> bounced\n", sampleLinux, 500},
		"mid-connection": {strings.Repeat(sampleLinux+"\n", 10) +
			"  1 <postmaster@example.com>: 550 5.1.1 <user@example.com> rejected\n", sampleFTD, 300},
	} {
		got, err := readAll(t, strings.NewReader(tc.input+strings.Repeat(tc.line+"\n", tc.n)), 0)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("%s: err = %v", name, err)
		}
		n := 0
		for _, m := range got {
			if m == tc.line {
				n++
			}
		}
		if n != tc.n {
			t.Errorf("%s: delivered %d of the %d lines after the counted-looking one", name, n, tc.n)
		}
	}
}

// The leftover of a line sender's counted-looking first line ends at an LF,
// a NUL that ends a frame, or EOF, and is delivered; a NUL followed by more
// text is part of the message.
func TestLeftoverTrailers(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"12 <13>hello world\x00<13>two\x00", []string{"<13>hello wo", "rld", "<13>two"}},
		{"12 <13>hello wor\x00ld\n<13>two\n", []string{"<13>hello wo", "r\x00ld", "<13>two"}},
		{"12 <13>hello world\r\n<13>two\r\n", []string{"<13>hello wo", "rld", "<13>two"}},
		{"12 <13>hello world", []string{"<13>hello wo", "rld"}},
	} {
		got, err := readAll(t, strings.NewReader(tc.in), 0)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("%q: err = %v", tc.in, err)
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A leftover longer than the cap is the head of an oversized line: it's
// delivered truncated, as any long line is, not dropped with the tail
// delivered as a message of its own.
func TestLongLeftoverKeepsHead(t *testing.T) {
	long := "<13>1 - - - - - - " + strings.Repeat("x", 200)
	got, err := readAll(t, strings.NewReader(octet(long)+long+"\n<13>next\n"), 100)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v", err)
	}
	// The counted copy is over the cap and dropped whole; the line after it
	// is the leftover, and keeps its head.
	want := []string{long[:100], "<13>next"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	// Exactly the cap, then EOF: all of it is delivered.
	got, _ = readAll(t, strings.NewReader("1 <"+strings.Repeat("A", 100)), 100)
	if len(got) != 2 || got[1] != strings.Repeat("A", 100) {
		t.Errorf("got %q", got)
	}
}

// Data lost to a read error (a timeout, reset or Kill) mid-message is
// counted, whichever way the message was framed.
func TestErrorPathAccounting(t *testing.T) {
	hdr := fmt.Sprintf("%d ", len(sampleFortiGate2))
	for name, tc := range map[string]struct {
		in            string
		bytes, frames int64
	}{
		"leftover":  {octet(sampleFortiGate1) + "leftover-no-trailer", int64(len("leftover-no-trailer")), 1},
		"line":      {sampleLinux + "\n" + "partial", int64(len("partial")), 1},
		"octet":     {octet(sampleFortiGate1) + octet(sampleFortiGate2)[:40], int64(40 - len(hdr)), 1},
		"oversized": {"99999999 <13>x", int64(len("<13>x")), 1},
	} {
		info := &ConnInfo{}
		fr := newFrameReader(bufio.NewReader(&errReader{tc.in, errTimeout}), 0)
		fr.info = info
		for range 100 {
			if _, err := fr.next(); err != nil {
				break
			}
		}
		if s := info.Snapshot(); s.DroppedBytes != tc.bytes || s.DroppedFrames != tc.frames {
			t.Errorf("%s: dropped %d bytes, %d frames; want %d, %d", name, s.DroppedBytes, s.DroppedFrames, tc.bytes, tc.frames)
		}
	}
}
