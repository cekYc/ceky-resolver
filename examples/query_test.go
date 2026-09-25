//go:build ignore

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

func buildQuery(domain string) []byte {
	var buf []byte

	// Header (12 bytes)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Flags: standard query, recursion desired
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCount: 1 question
	buf = append(buf, header...)

	// Question section - domain name
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0) // null terminator

	// QType: A (1), QClass: IN (1)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], 1) // A record
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN class
	buf = append(buf, tail...)

	return buf
}

func main() {
	domain := "google.com"
	query := buildQuery(domain)

	conn, err := net.DialTimeout("udp", "127.0.0.1:53", 3*time.Second)
	if err != nil {
		fmt.Println("Bağlantı hatası:", err)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write(query)
	if err != nil {
		fmt.Println("Gönderme hatası:", err)
		return
	}

	fmt.Printf("Sorgu gönderildi: %s\n", domain)

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		fmt.Println("Yanıt alınamadı:", err)
		return
	}

	fmt.Printf("Yanıt alındı: %d byte\n", n)

	// Header'ı ayrıştır
	if n >= 12 {
		ancount := binary.BigEndian.Uint16(response[6:8])
		fmt.Printf("Cevap sayısı (ANCount): %d\n", ancount)
	}

	// Answer bölümünden IP adreslerini çıkar
	// Soru bölümünü atla
	offset := 12
	// Domain adını atla
	for response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset++    // null byte
	offset += 4 // QType + QClass

	// Answer kayıtlarını oku
	ancount := binary.BigEndian.Uint16(response[6:8])
	for i := 0; i < int(ancount); i++ {
		if offset+12 > n {
			break
		}
		// Name (pointer veya label)
		if response[offset]&0xC0 == 0xC0 {
			offset += 2 // pointer
		} else {
			for response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}

		rtype := binary.BigEndian.Uint16(response[offset : offset+2])
		rdlength := binary.BigEndian.Uint16(response[offset+8 : offset+10])
		offset += 10

		if rtype == 1 && rdlength == 4 { // A record
			ip := net.IPv4(response[offset], response[offset+1], response[offset+2], response[offset+3])
			fmt.Printf("  %s -> %s\n", domain, ip)
		}
		offset += int(rdlength)
	}
}
