package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPanelSecurity(t *testing.T) {
	setupGlobals(t, testResolver("1", "127.0.0.99"))
	handler := securePanel(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(method, host, token string) int {
		req := httptest.NewRequest(method, "http://"+host+"/api/app/protection", strings.NewReader("{}"))
		req.Host = host
		if token != "" {
			req.Header.Set("X-Ceky-Token", token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if do("GET", "127.0.0.1:9090", "") != 200 || do("GET", "localhost:9090", "") != 200 || do("GET", "[::1]:9090", "") != 200 {
		t.Fatal("yerel okuma istekleri kabul edilmeli")
	}
	// DNS rebinding: saldırganın alan adı 127.0.0.1'e çözülse bile Host başlığı farklıdır
	if do("GET", "evil.example.com:9090", "") != 403 {
		t.Fatal("yabancı Host başlığı reddedilmeli")
	}
	// CSRF: başka bir site token'ı bilemez
	if do("POST", "127.0.0.1:9090", "") != 403 || do("POST", "127.0.0.1:9090", "yanlis") != 403 {
		t.Fatal("token'sız değişiklik isteği reddedilmeli")
	}
	if do("POST", "127.0.0.1:9090", app.token) != 200 {
		t.Fatal("doğru token ile istek kabul edilmeli")
	}
}

func TestPanelPageAndAPIs(t *testing.T) {
	setupGlobals(t, testResolver("1", "127.0.0.99"))
	app.dnsAddrs = []string{"127.0.0.1"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://127.0.0.1:9090/", nil)
	handleDashboardPage(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, app.token) || strings.Contains(body, "{{CEKY_TOKEN}}") {
		t.Fatal("sayfaya token yerleştirilmeli")
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("panel başka sitelere açılmamalı")
	}

	for _, path := range []string{"/api/stats", "/api/queries", "/api/app/state", "/api/app/ping"} {
		rec := httptest.NewRecorder()
		mux := http.NewServeMux()
		mux.HandleFunc("/api/stats", handleAPIStats)
		mux.HandleFunc("/api/queries", handleAPIQueries)
		mux.HandleFunc("/api/app/state", handleAPIState)
		mux.HandleFunc("/api/app/ping", handleAPIPing)
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: kod %d", path, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: CORS başlığı olmamalı (sorgu geçmişi sızar)", path)
		}
	}
}
