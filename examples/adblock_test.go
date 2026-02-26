//go:build ignore

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

func buildTestQuery(domain string) []byte {
	var packet []byte

	// Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xBBBB) // ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCount=1
	packet = append(packet, header...)

	// Question — domain name
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		packet = append(packet, byte(len(part)))
		packet = append(packet, []byte(part)...)
	}
	packet = append(packet, 0x00) // Null terminator

	// QType=A(1), QClass=IN(1)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], 1)
	binary.BigEndian.PutUint16(tail[2:4], 1)
	packet = append(packet, tail...)

	return packet
}

func testDomain(conn *net.UDPConn, serverAddr *net.UDPAddr, domain string) {
	query := buildTestQuery(domain)
	_, err := conn.WriteToUDP(query, serverAddr)
	if err != nil {
		fmt.Printf("  ✗ %s — gönderme hatası: %v\n", domain, err)
		return
	}

	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		fmt.Printf("  ✗ %s — yanıt yok\n", domain)
		return
	}

	if n < 12 {
		return
	}

	anCount := binary.BigEndian.Uint16(buf[6:8])
	if anCount > 0 && n >= 16 {
		// Son 4 byte'ı kontrol et (IP adresi)
		ip := buf[n-4 : n]
		ipStr := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
		if ipStr == "0.0.0.0" {
			fmt.Printf("  🛡️ %s → 0.0.0.0 (ENGELLENDİ)\n", domain)
		} else {
			fmt.Printf("  ✓  %s → %s\n", domain, ipStr)
		}
	} else {
		fmt.Printf("  ?  %s → yanıt: %d byte, %d cevap\n", domain, n, anCount)
	}
}

func main() {
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("╔══ Ceky Resolver v3.0 — Ad-Block Testi ══╗")
	fmt.Println()

	// Normal domain'ler (çözümlenmeli)
	fmt.Println("Normal Domain'ler (geçmeli):")
	testDomain(conn, serverAddr, "google.com")
	testDomain(conn, serverAddr, "github.com")

	// Reklam/takipçi domain'leri (engellenecek — blocklist yüklendiyse)
	fmt.Println()
	fmt.Println("Reklam Domain'leri (engellenmeli):")
	testDomain(conn, serverAddr, "ads.google.com")
	testDomain(conn, serverAddr, "analytics.google.com")
	testDomain(conn, serverAddr, "ad.doubleclick.net")
	testDomain(conn, serverAddr, "pagead2.googlesyndication.com")
	testDomain(conn, serverAddr, "tracking.example.com")

	fmt.Println()
	fmt.Println("╚══════════════════════════════════════════╝")
}
