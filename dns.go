package main

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
)

// ==================== DNS SABİTLERİ ====================

const (
	typeA     uint16 = 1
	typeNS    uint16 = 2
	typeCNAME uint16 = 5
	typeSOA   uint16 = 6
	typePTR   uint16 = 12
	typeMX    uint16 = 15
	typeTXT   uint16 = 16
	typeAAAA  uint16 = 28
	typeSRV   uint16 = 33
	typeDNAME uint16 = 39
	typeOPT   uint16 = 41
	typeHTTPS uint16 = 65
	typeANY   uint16 = 255

	classIN uint16 = 1

	rcodeSuccess  = 0
	rcodeFormErr  = 1
	rcodeServFail = 2
	rcodeNXDomain = 3
	rcodeNotImp   = 4
	rcodeRefused  = 5

	flagQR     uint16 = 0x8000
	flagOpcode uint16 = 0x7800
	flagAA     uint16 = 0x0400
	flagTC     uint16 = 0x0200
	flagRD     uint16 = 0x0100
	flagRA     uint16 = 0x0080

	// DNS Flag Day 2020 önerisi — parçalanmayan güvenli UDP boyutu
	ednsUDPSize = 1232
)

var errMalformed = errors.New("bozuk DNS paketi")

// ==================== YAPILAR (STRUCTS) ====================

// DNSHeader — DNS paket başlığı (12 byte)
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Rcode — yanıt kodu (alt 4 bit)
func (h DNSHeader) Rcode() int { return int(h.Flags & 0x000F) }

// DNSQuestion — DNS soru bölümü
type DNSQuestion struct {
	Name   string
	QType  uint16
	QClass uint16
}

// DNSRecord — Ayrıştırılmış DNS kaydı (Answer, Authority, Additional).
// RData içindeki alan adları sıkıştırmasız (düz) wire formatında tutulur,
// böylece kayıt başka bir pakete güvenle kopyalanabilir.
type DNSRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

// DNSMessage — Tam bir DNS mesajı
type DNSMessage struct {
	Header     DNSHeader
	Questions  []DNSQuestion
	Answers    []DNSRecord
	Authority  []DNSRecord
	Additional []DNSRecord
}

// ==================== AYRIŞTIRMA (PARSING) ====================

// Byte dizisini DNSHeader'a dönüştür (buf en az 12 byte olmalı)
func parseHeader(buf []byte) DNSHeader {
	return DNSHeader{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   binary.BigEndian.Uint16(buf[2:4]),
		QDCount: binary.BigEndian.Uint16(buf[4:6]),
		ANCount: binary.BigEndian.Uint16(buf[6:8]),
		NSCount: binary.BigEndian.Uint16(buf[8:10]),
		ARCount: binary.BigEndian.Uint16(buf[10:12]),
	}
}

// readName — (sıkıştırılmış olabilen) alan adını okuyup düz wire formatında döndürür.
// İşaretçiler yalnızca geriye bakabilir; bu sayede kötü niyetli döngüler imkansızdır.
func readName(buf []byte, offset int) ([]byte, int, error) {
	wire := make([]byte, 0, 32)
	end := -1
	for jumps := 0; ; {
		if offset >= len(buf) {
			return nil, 0, errMalformed
		}
		length := int(buf[offset])
		switch {
		case length == 0: // Kök etiketi — isim bitti
			wire = append(wire, 0)
			if end < 0 {
				end = offset + 1
			}
			return wire, end, nil

		case length&0xC0 == 0xC0: // Sıkıştırma işaretçisi
			if offset+1 >= len(buf) {
				return nil, 0, errMalformed
			}
			ptr := int(binary.BigEndian.Uint16(buf[offset:offset+2]) & 0x3FFF)
			if end < 0 {
				end = offset + 2
			}
			jumps++
			if ptr >= offset || jumps > 64 {
				return nil, 0, errMalformed
			}
			offset = ptr

		case length > 63: // 0x40 / 0x80 — desteklenmeyen etiket türleri
			return nil, 0, errMalformed

		default: // Normal etiket
			if offset+1+length > len(buf) || len(wire)+1+length+1 > 255 {
				return nil, 0, errMalformed
			}
			wire = append(wire, buf[offset:offset+1+length]...)
			offset += 1 + length
		}
	}
}

// wireToName — düz wire formatındaki ismi "www.example.com" biçimine çevir
func wireToName(wire []byte) string {
	var sb strings.Builder
	for i := 0; i < len(wire); {
		l := int(wire[i])
		if l == 0 || i+1+l > len(wire) {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(wire[i+1 : i+1+l])
		i += 1 + l
	}
	return sb.String()
}

// Domain adını wire formatından ayrıştır (compression pointer desteği ile)
func parseDomainName(buf []byte, offset int) (string, int, error) {
	wire, next, err := readName(buf, offset)
	if err != nil {
		return "", 0, err
	}
	return wireToName(wire), next, nil
}

// DNS soru kısmını ayrıştır
func parseQuestion(buf []byte, offset int) (DNSQuestion, int, error) {
	name, off, err := parseDomainName(buf, offset)
	if err != nil {
		return DNSQuestion{}, 0, err
	}
	if off+4 > len(buf) {
		return DNSQuestion{}, 0, errMalformed
	}
	return DNSQuestion{
		Name:   name,
		QType:  binary.BigEndian.Uint16(buf[off : off+2]),
		QClass: binary.BigEndian.Uint16(buf[off+2 : off+4]),
	}, off + 4, nil
}

// expandRData — RData içindeki sıkıştırılmış alan adlarını açar.
// Bu yapılmazsa işaretçiler başka pakete kopyalandığında bozuk veri üretir.
func expandRData(buf []byte, start, length int, rtype uint16) ([]byte, error) {
	end := start + length
	msg := buf[:end] // İsimler RData dışına taşamaz
	switch rtype {
	case typeNS, typeCNAME, typePTR, typeDNAME:
		wire, next, err := readName(msg, start)
		if err != nil || next != end {
			return nil, errMalformed
		}
		return wire, nil

	case typeMX: // tercih (2) + isim
		if length < 3 {
			return nil, errMalformed
		}
		wire, next, err := readName(msg, start+2)
		if err != nil || next != end {
			return nil, errMalformed
		}
		return append(append([]byte{}, buf[start:start+2]...), wire...), nil

	case typeSRV: // öncelik + ağırlık + port (6) + hedef
		if length < 7 {
			return nil, errMalformed
		}
		wire, next, err := readName(msg, start+6)
		if err != nil || next != end {
			return nil, errMalformed
		}
		return append(append([]byte{}, buf[start:start+6]...), wire...), nil

	case typeSOA: // mname + rname + 5×uint32
		mname, off, err := readName(msg, start)
		if err != nil {
			return nil, errMalformed
		}
		rname, off, err := readName(msg, off)
		if err != nil || end-off != 20 {
			return nil, errMalformed
		}
		out := append(append([]byte{}, mname...), rname...)
		return append(out, buf[off:end]...), nil
	}

	rdata := make([]byte, length)
	copy(rdata, buf[start:end])
	return rdata, nil
}

// Tek bir kaydı ayrıştır
func parseRecord(buf []byte, offset int) (DNSRecord, int, error) {
	name, off, err := parseDomainName(buf, offset)
	if err != nil {
		return DNSRecord{}, 0, err
	}
	if off+10 > len(buf) {
		return DNSRecord{}, 0, errMalformed
	}
	rr := DNSRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(buf[off : off+2]),
		Class: binary.BigEndian.Uint16(buf[off+2 : off+4]),
		TTL:   binary.BigEndian.Uint32(buf[off+4 : off+8]),
	}
	rdlength := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
	off += 10
	if off+rdlength > len(buf) {
		return DNSRecord{}, 0, errMalformed
	}
	rr.RData, err = expandRData(buf, off, rdlength, rr.Type)
	if err != nil {
		return DNSRecord{}, 0, err
	}
	return rr, off + rdlength, nil
}

// DNS kayıtlarını ayrıştır (Answer, Authority veya Additional bölümü)
func parseRecords(buf []byte, offset int, count uint16) ([]DNSRecord, int, error) {
	records := make([]DNSRecord, 0, min(int(count), 64))
	for i := 0; i < int(count); i++ {
		rr, next, err := parseRecord(buf, offset)
		if err != nil {
			return records, offset, err
		}
		records = append(records, rr)
		offset = next
	}
	return records, offset, nil
}

// parseMessage — tam bir DNS mesajını sınır kontrolleriyle ayrıştırır
func parseMessage(buf []byte) (*DNSMessage, error) {
	if len(buf) < 12 {
		return nil, errMalformed
	}
	msg := &DNSMessage{Header: parseHeader(buf)}
	off := 12
	for i := 0; i < int(msg.Header.QDCount); i++ {
		q, next, err := parseQuestion(buf, off)
		if err != nil {
			return nil, err
		}
		msg.Questions = append(msg.Questions, q)
		off = next
	}
	var err error
	if msg.Answers, off, err = parseRecords(buf, off, msg.Header.ANCount); err != nil {
		return nil, err
	}
	if msg.Authority, off, err = parseRecords(buf, off, msg.Header.NSCount); err != nil {
		return nil, err
	}
	// Additional bölümündeki hatalar ölümcül değil — okunabilen kadarını al
	msg.Additional, _, _ = parseRecords(buf, off, msg.Header.ARCount)
	return msg, nil
}

// ednsSize — istemcinin EDNS0 ile bildirdiği UDP boyutu (yoksa 0)
func ednsSize(msg *DNSMessage) int {
	for _, rr := range msg.Additional {
		if rr.Type == typeOPT {
			return max(int(rr.Class), 512)
		}
	}
	return 0
}

// ==================== YARDIMCI İSİM FONKSİYONLARI ====================

// normalizeName — küçük harf, sondaki nokta yok
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// isSubdomain — child, parent'ın kendisi ya da alt alanı mı? ("" = kök)
func isSubdomain(child, parent string) bool {
	child, parent = normalizeName(child), normalizeName(parent)
	if parent == "" || child == parent {
		return true
	}
	return strings.HasSuffix(child, "."+parent)
}

// parentName — "www.example.com" → "example.com" → "com" → ""
func parentName(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// rdataName — NS/CNAME/PTR kayıtlarının hedef ismi
func rdataName(rdata []byte) string {
	return normalizeName(wireToName(rdata))
}

// recordIP — A/AAAA kaydındaki IP adresi
func recordIP(rr DNSRecord) string {
	if (rr.Type == typeA && len(rr.RData) == 4) || (rr.Type == typeAAAA && len(rr.RData) == 16) {
		return net.IP(rr.RData).String()
	}
	return ""
}

// soaMinimum — SOA kaydından olumsuz önbellek süresi (RFC 2308: min(TTL, MINIMUM))
func soaMinimum(rr DNSRecord) uint32 {
	if rr.Type != typeSOA || len(rr.RData) < 20 {
		return 0
	}
	minimum := binary.BigEndian.Uint32(rr.RData[len(rr.RData)-4:])
	return min(minimum, rr.TTL)
}

// ==================== PAKET OLUŞTURMA ====================

// Domain adını DNS wire formatına dönüştür
func domainToBytes(domain string) []byte {
	var buf []byte
	for _, part := range strings.Split(domain, ".") {
		if len(part) == 0 {
			continue
		}
		if len(part) > 63 {
			part = part[:63]
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, part...)
	}
	return append(buf, 0)
}

// msgBuilder — isim sıkıştırmalı basit mesaj yazıcı
type msgBuilder struct {
	buf   []byte
	names map[string]int
}

func newMsgBuilder() *msgBuilder {
	return &msgBuilder{buf: make([]byte, 12, 512), names: make(map[string]int)}
}

func (b *msgBuilder) writeName(name string) {
	key := normalizeName(name)
	if off, ok := b.names[key]; ok {
		b.buf = append(b.buf, byte(0xC0|off>>8), byte(off))
		return
	}
	if key != "" && len(b.buf) < 0x3FFF {
		b.names[key] = len(b.buf)
	}
	b.buf = append(b.buf, domainToBytes(name)...)
}

func (b *msgBuilder) writeRecord(rr DNSRecord) {
	b.writeName(rr.Name)
	b.buf = binary.BigEndian.AppendUint16(b.buf, rr.Type)
	b.buf = binary.BigEndian.AppendUint16(b.buf, rr.Class)
	b.buf = binary.BigEndian.AppendUint32(b.buf, rr.TTL)
	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(len(rr.RData)))
	b.buf = append(b.buf, rr.RData...)
}

func (b *msgBuilder) writeOPT() {
	b.buf = append(b.buf, 0) // kök isim
	b.buf = binary.BigEndian.AppendUint16(b.buf, typeOPT)
	b.buf = binary.BigEndian.AppendUint16(b.buf, ednsUDPSize)
	b.buf = binary.BigEndian.AppendUint32(b.buf, 0) // extended RCODE, sürüm, bayraklar
	b.buf = binary.BigEndian.AppendUint16(b.buf, 0) // RDLENGTH
}

func (b *msgBuilder) finish(h DNSHeader) []byte {
	binary.BigEndian.PutUint16(b.buf[0:2], h.ID)
	binary.BigEndian.PutUint16(b.buf[2:4], h.Flags)
	binary.BigEndian.PutUint16(b.buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(b.buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(b.buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(b.buf[10:12], h.ARCount)
	return b.buf
}

// Yukarı akış (upstream) sunuculara gönderilecek sorgu paketi (EDNS0 destekli).
// ID, kriptografik kalitede rastgele üretilir (önbellek zehirlenmesine karşı).
func buildQuery(domain string, qtype uint16) []byte {
	b := newMsgBuilder()
	b.buf = append(b.buf, domainToBytes(domain)...)
	b.buf = binary.BigEndian.AppendUint16(b.buf, qtype)
	b.buf = binary.BigEndian.AppendUint16(b.buf, classIN)
	// Kök sunucular EDNS0 olmadan büyük yanıtları keser (TC=1)
	b.writeOPT()
	return b.finish(DNSHeader{
		ID:      uint16(rand.Uint32()),
		Flags:   0, // Standart sorgu, özyineleme istenmiyor (RD=0)
		QDCount: 1,
		ARCount: 1,
	})
}

// buildReply — istemciye gönderilecek yanıt paketini oluştur.
// udpLimit > 0 ise ve yanıt bu boyutu aşarsa kayıtlar atılır, TC=1 işaretlenir
// (istemci TCP ile yeniden sorar).
func buildReply(req *DNSMessage, rcode int, answers, authority []DNSRecord, udpLimit int) []byte {
	edns := ednsSize(req) > 0
	build := func(ans, auth []DNSRecord, truncated bool) []byte {
		b := newMsgBuilder()
		h := DNSHeader{
			ID:    req.Header.ID,
			Flags: flagQR | flagRA | req.Header.Flags&(flagOpcode|flagRD) | uint16(rcode&0xF),
		}
		if truncated {
			h.Flags |= flagTC
		}
		if len(req.Questions) > 0 {
			q := req.Questions[0]
			b.writeName(q.Name)
			b.buf = binary.BigEndian.AppendUint16(b.buf, q.QType)
			b.buf = binary.BigEndian.AppendUint16(b.buf, q.QClass)
			h.QDCount = 1
		}
		for _, rr := range ans {
			b.writeRecord(rr)
		}
		for _, rr := range auth {
			b.writeRecord(rr)
		}
		h.ANCount, h.NSCount = uint16(len(ans)), uint16(len(auth))
		if edns {
			b.writeOPT()
			h.ARCount = 1
		}
		return b.finish(h)
	}

	resp := build(answers, authority, false)
	if udpLimit > 0 && len(resp) > udpLimit {
		resp = build(nil, nil, true)
	}
	return resp
}

// buildErrorReply — ayrıştırılamayan istekler için yalnızca başlıktan oluşan yanıt
func buildErrorReply(raw []byte, rcode int) []byte {
	h := parseHeader(raw)
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], h.ID)
	binary.BigEndian.PutUint16(resp[2:4], flagQR|flagRA|h.Flags&(flagOpcode|flagRD)|uint16(rcode&0xF))
	return resp
}

// Engelli domain yanıtı (Pi-hole "NULL" modu): A → 0.0.0.0, AAAA → ::, diğerleri boş
func blockedRecords(q DNSQuestion) []DNSRecord {
	switch q.QType {
	case typeA:
		return []DNSRecord{{Name: q.Name, Type: typeA, Class: classIN, TTL: 60, RData: make([]byte, 4)}}
	case typeAAAA:
		return []DNSRecord{{Name: q.Name, Type: typeAAAA, Class: classIN, TTL: 60, RData: make([]byte, 16)}}
	}
	return nil
}
