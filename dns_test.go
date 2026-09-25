package main

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

func TestParseRejectsPointerLoop(t *testing.T) {
	// Başlık + kendini gösteren isim işaretçisi (0xC00C @ 12)
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	pkt = append(pkt, 0xC0, 0x0C, 0, 1, 0, 1)
	if _, err := parseMessage(pkt); err == nil {
		t.Fatal("işaretçi döngüsü reddedilmeli")
	}

	// İleriyi gösteren işaretçi
	pkt = make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	pkt = append(pkt, 0xC0, 0x20, 0, 1, 0, 1)
	if _, err := parseMessage(pkt); err == nil {
		t.Fatal("ileri işaretçi reddedilmeli")
	}
}

func TestCompressedRDataIsExpanded(t *testing.T) {
	// Soru: example.test MX — yanıttaki MX hedefi "mail" + soru ismine işaretçi
	b := newMsgBuilder()
	b.buf = append(b.buf, domainToBytes("example.test")...)
	b.buf = binary.BigEndian.AppendUint16(b.buf, typeMX)
	b.buf = binary.BigEndian.AppendUint16(b.buf, classIN)
	b.buf = append(b.buf, 0xC0, 0x0C) // sahip ismi: soru
	b.buf = binary.BigEndian.AppendUint16(b.buf, typeMX)
	b.buf = binary.BigEndian.AppendUint16(b.buf, classIN)
	b.buf = binary.BigEndian.AppendUint32(b.buf, 300)
	rdata := []byte{0, 10, 4, 'm', 'a', 'i', 'l', 0xC0, 0x0C}
	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(len(rdata)))
	b.buf = append(b.buf, rdata...)
	pkt := b.finish(DNSHeader{ID: 1, Flags: flagQR, QDCount: 1, ANCount: 1})

	msg, err := parseMessage(pkt)
	if err != nil {
		t.Fatal(err)
	}
	mx := msg.Answers[0]
	if got := wireToName(mx.RData[2:]); got != "mail.example.test" {
		t.Fatalf("MX hedefi açılmalı, gelen %q", got)
	}

	// Başka bir pakete kopyalandığında da doğru kalmalı
	req := &DNSMessage{Header: DNSHeader{ID: 7}, Questions: []DNSQuestion{{Name: "other.zz", QType: typeMX, QClass: classIN}}}
	out, err := parseMessage(buildReply(req, rcodeSuccess, []DNSRecord{mx}, nil, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got := wireToName(out.Answers[0].RData[2:]); got != "mail.example.test" {
		t.Fatalf("yeniden paketlenen MX bozuk: %q", got)
	}
}

func TestBuildReplyTruncatesForUDP(t *testing.T) {
	req, _ := parseMessage(makeQuery("big.test", typeTXT, false))
	var records []DNSRecord
	for i := 0; i < 20; i++ {
		records = append(records, DNSRecord{Name: "big.test", Type: typeTXT, Class: classIN, TTL: 60, RData: make([]byte, 100)})
	}
	resp, err := parseMessage(buildReply(req, rcodeSuccess, records, nil, 512))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Flags&flagTC == 0 || len(resp.Answers) != 0 {
		t.Fatal("512 byte'ı aşan UDP yanıtı TC=1 ile kırpılmalı")
	}
	full, _ := parseMessage(buildReply(req, rcodeSuccess, records, nil, 0))
	if len(full.Answers) != 20 {
		t.Fatal("TCP yanıtı kırpılmamalı")
	}
}

func TestBuildReplyEchoesEDNSAndFlags(t *testing.T) {
	req, _ := parseMessage(makeQuery("example.test", typeA, true))
	resp, _ := parseMessage(buildReply(req, rcodeNXDomain, nil, nil, 0))
	if resp.Header.ID != req.Header.ID || resp.Header.Rcode() != rcodeNXDomain {
		t.Fatal("ID ve RCODE korunmalı")
	}
	if resp.Header.Flags&flagRD == 0 || resp.Header.Flags&flagRA == 0 || resp.Header.Flags&flagQR == 0 {
		t.Fatalf("QR/RD/RA bayrakları eksik: %04x", resp.Header.Flags)
	}
	if ednsSize(resp) == 0 {
		t.Fatal("EDNS'li isteğe OPT kaydıyla yanıt verilmeli")
	}
}

func TestParseRandomGarbageDoesNotPanic(t *testing.T) {
	seed := makeQuery("www.example.test", typeA, true)
	for i := 0; i < 20000; i++ {
		pkt := append([]byte(nil), seed...)
		for j := 0; j < 1+rand.IntN(6); j++ {
			pkt[rand.IntN(len(pkt))] = byte(rand.Uint32())
		}
		pkt = pkt[:rand.IntN(len(pkt)+1)]
		parseMessage(pkt) // panik olmamalı
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add(makeQuery("example.com", typeA, true))
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if msg, err := parseMessage(data); err == nil && len(msg.Questions) > 0 {
			buildReply(msg, rcodeSuccess, msg.Answers, msg.Authority, 512)
		}
	})
}

func TestIsSubdomain(t *testing.T) {
	cases := []struct {
		child, parent string
		want          bool
	}{
		{"www.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "", true},
		{"badexample.com", "example.com", false},
		{"com", "example.com", false},
	}
	for _, c := range cases {
		if got := isSubdomain(c.child, c.parent); got != c.want {
			t.Errorf("isSubdomain(%q, %q) = %v", c.child, c.parent, got)
		}
	}
}
