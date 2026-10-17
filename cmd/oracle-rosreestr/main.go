// Сервис-эмулятор оракула Росреестра.
//
// Поддерживает два режима транспорта:
//   - HTTP (для быстрого локального прототипа);
//   - HTTPS с mTLS (двусторонняя аутентификация, для демонстрации
//     защищённого контура).
//
// Режим выбирается через секцию tls в конфиге.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
	"nis-core/internal/oracle"
)

// Config — конфигурация сервиса-эмулятора.
type Config struct {
	ListenAddr        string  `yaml:"listen_addr"`
	PrivateKeyHex     string  `yaml:"private_key_hex"`
	GenerateIfMissing bool    `yaml:"generate_if_missing"`
	LogRequests       bool    `yaml:"log_requests"`
	TLS               TLSConf `yaml:"tls"`
}

// TLSConf — настройки mTLS-транспорта.
type TLSConf struct {
	Enabled        bool   `yaml:"enabled"`
	CACertPath     string `yaml:"ca_cert_path"`
	ServerCertPath string `yaml:"server_cert_path"`
	ServerKeyPath  string `yaml:"server_key_path"`
	GenerateIfMiss bool   `yaml:"generate_if_missing"`
	CertDir        string `yaml:"cert_dir"`
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8081"
	}
	if cfg.TLS.Enabled && cfg.TLS.CertDir == "" {
		cfg.TLS.CertDir = "./certs"
	}
	return &cfg, nil
}

// Server — HTTP-обработчик оракула.
type Server struct {
	g         *crypto.GOSTProvider
	priv      *gost3410.PrivateKey
	pub       *gost3410.PublicKey
	logReqs   bool
	alwaysRej bool

	requestsTotal atomic.Uint64
	requestsOK    atomic.Uint64
	requestsRej   atomic.Uint64
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.requestsTotal.Add(1)

	var req oracle.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.DealID == "" || req.Kadastr == "" {
		http.Error(w, "deal_id and kadastr are required", http.StatusBadRequest)
		return
	}

	success := !s.alwaysRej
	if req.Trigger == "" {
		http.Error(w, "trigger is required", http.StatusBadRequest)
		return
	}
	digest := s.g.OracleResponseDigest(req.DealID, req.Kadastr, req.Trigger, success)
	sig, err := s.g.SignGOST3410(s.priv, digest)
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := oracle.RegisterResponse{
		DealID:    req.DealID,
		Kadastr:   req.Kadastr,
		Trigger:   req.Trigger,
		Success:   success,
		Signature: sig,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[oracle] encode response: %v", err)
	}

	if success {
		s.requestsOK.Add(1)
	} else {
		s.requestsRej.Add(1)
	}
	if s.logReqs {
		log.Printf("[oracle] deal=%s kadastr=%s trigger=%s success=%v",
			req.DealID, req.Kadastr, req.Trigger, success)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ok total=%d ok=%d rejected=%d\n",
		s.requestsTotal.Load(), s.requestsOK.Load(), s.requestsRej.Load())
}

func resolveKeypair(
	g *crypto.GOSTProvider,
	privHex string,
	generate bool,
) (*gost3410.PrivateKey, *gost3410.PublicKey, error) {
	if privHex == "" {
		if !generate {
			return nil, nil, errors.New(
				"private_key_hex is empty and generate_if_missing is false")
		}
		priv, pub, err := g.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		log.Printf("[oracle] generated private: %s", hex.EncodeToString(priv.Raw()))
		log.Printf("[oracle] generated public : %s", hex.EncodeToString(pub.Raw()))
		return priv, pub, nil
	}
	raw, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode private_key_hex: %w", err)
	}
	priv, err := g.NewPrivateKeyFromRaw(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("derive public key: %w", err)
	}
	log.Printf("[oracle] public key: %s", hex.EncodeToString(pub.Raw()))
	return priv, pub, nil
}

// buildTLSConfig готовит tls.Config с RequireAndVerifyClientCert.
// Сертификаты генерируются при первом запуске, если их нет.
func buildTLSConfig(cfg TLSConf) (*tls.Config, error) {
	// Проверяем наличие сертификатов, при необходимости — генерируем.
	if _, err := os.Stat(cfg.CACertPath); os.IsNotExist(err) {
		if !cfg.GenerateIfMiss {
			return nil, fmt.Errorf("ca cert not found at %s", cfg.CACertPath)
		}
		log.Printf("[oracle] generating self-signed cert bundle in %s", cfg.CertDir)
		bundle, err := oracle.GenerateCertBundle(cfg.CertDir)
		if err != nil {
			return nil, fmt.Errorf("generate certs: %w", err)
		}
		// Если пути в конфиге не совпадают с дефолтными — перезапишем.
		cfg.CACertPath = bundle.CAPath
		cfg.ServerCertPath = bundle.ServerCertPath
		cfg.ServerKeyPath = bundle.ServerKeyPath
		log.Printf("[oracle] certs generated:\n  CA:     %s\n  server: %s\n  key:    %s",
			bundle.CAPath, bundle.ServerCertPath, bundle.ServerKeyPath)
		log.Printf("[oracle] client cert (for nis-node): %s / %s",
			bundle.ClientCertPath, bundle.ClientKeyPath)
	}

	caPEM, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca.crt has no valid certificates")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server pair: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func main() {
	configPath := flag.String("config", "configs/oracle-mock.yaml", "path to YAML config")
	listenOverride := flag.String("listen", "", "override listen address")
	rejectAll := flag.Bool("reject", false, "always reject registrations")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("[oracle] %v", err)
	}
	if *listenOverride != "" {
		cfg.ListenAddr = *listenOverride
	}

	g := crypto.NewGOSTProvider()
	priv, pub, err := resolveKeypair(g, cfg.PrivateKeyHex, cfg.GenerateIfMissing)
	if err != nil {
		log.Fatalf("[oracle] keys: %v", err)
	}

	srv := &Server{
		g:         g,
		priv:      priv,
		pub:       pub,
		logReqs:   cfg.LogRequests,
		alwaysRej: *rejectAll,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/register", srv.handleRegister)
	mux.HandleFunc("/healthz", srv.handleHealthz)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	if cfg.TLS.Enabled {
		tlsCfg, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			log.Fatalf("[oracle] tls: %v", err)
		}
		httpSrv.TLSConfig = tlsCfg
		go func() {
			log.Printf("[oracle] HTTPS listening on %s (mTLS required)", cfg.ListenAddr)
			if err := httpSrv.ListenAndServeTLS("", ""); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[oracle] listen tls: %v", err)
			}
		}()
	} else {
		go func() {
			log.Printf("[oracle] HTTP listening on %s (no TLS)", cfg.ListenAddr)
			if err := httpSrv.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[oracle] listen: %v", err)
			}
		}()
	}

	<-stop
	log.Println("[oracle] shutdown signal received, stopping...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("[oracle] shutdown error: %v", err)
	}
	log.Printf("[oracle] stopped. total=%d ok=%d rejected=%d",
		srv.requestsTotal.Load(), srv.requestsOK.Load(), srv.requestsRej.Load())
}
