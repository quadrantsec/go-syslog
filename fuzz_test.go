package syslog

import (
	"bufio"
	"io"
	"testing"

	"gopkg.in/mcuadros/go-syslog.v2/format"
)

func addFrameSeeds(f *testing.F) {
	for _, s := range []string{
		octet(sampleFortiGate1) + octet(sampleFortiGate2),
		octet(sampleBarracuda) + "\n" + octet(sampleLinux) + "\n",
		sampleLinux + "\n" + sampleFTD + "\r\n",
		sampleSophos + "\x00" + sampleSophos + "\x00",
		"<13>abc\x00def\n5 <x>yz\n",
		"99999999 <13>x",
		"12" + octet(sampleFortiGate2) + "8443297 <189>1",
		"\n\r \x00\t",
	} {
		f.Add([]byte(s))
	}
}

// FuzzFrameReader feeds arbitrary bytes through a tiny buffer, so frames
// straddle buffer refills everywhere, ending at EOF or at a timeout. The
// reader must not panic, must stop at the end, must honor the cap, and must
// never deliver and count as dropped more bytes than it read.
func FuzzFrameReader(f *testing.F) {
	addFrameSeeds(f)
	f.Add([]byte("2 <a@example.com> 3 <b@example.com> bounced\n<13>x\n"))
	f.Add([]byte("12 <13>hello wor\x00ld\n<13>two\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, end := range []error{io.EOF, errTimeout} {
			const max = 512
			info := &ConnInfo{}
			fr := newFrameReader(bufio.NewReaderSize(&errReader{string(data), end}, 16), max)
			fr.info = info
			total := 0
			done := false
			for range len(data) + 2 {
				msg, err := fr.next()
				if len(msg) > max {
					t.Fatalf("message of %d bytes over the %d byte cap", len(msg), max)
				}
				total += len(msg)
				if err != nil {
					if dropped := info.Snapshot().DroppedBytes; int64(total)+dropped > int64(len(data)) {
						t.Fatalf("delivered %d and dropped %d bytes from %d bytes of input", total, dropped, len(data))
					}
					done = true
					break
				}
			}
			if !done {
				t.Fatalf("no end after %d calls on %d bytes", len(data)+2, len(data))
			}
		}
	})
}

// FuzzParsers checks that no parser panics on arbitrary input. (The server
// recovers parser panics, but a panic still drops the message.)
func FuzzParsers(f *testing.F) {
	for _, s := range []string{sampleFortiGate1, sampleBarracuda, sampleLinux, sampleSophos, sampleFTD,
		"<13>1 2026-11-12T04:00:00.123456789Z host app - - - msg", "<", "<1>", "<191>1 - - - - - -"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, fm := range []format.Format{RFC3164, RFC5424, RFC6587, Automatic} {
			p := fm.GetParser(data)
			_ = p.Parse()
			_ = p.Dump()
		}
	})
}
