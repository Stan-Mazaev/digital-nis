// Package app собирает компоненты «Цифровой НИС» в единый узел:
// хранилище, криптопровайдер, движок эскроу, клиент и верификатор
// оракула Росреестра.
//
// В продакшене роли разделены между узлами:
//   - узел эмитента (Росвоенипотека) знает только свой приватный ключ;
//   - узел оракула (Росреестр) знает только свой приватный ключ;
//   - узел проверки (Минобороны) знает публичные ключи обеих сторон.
//
// В демонстрационном прототипе один процесс может держать приватные
// ключи обеих сторон, чтобы прогнать сквозной сценарий без сети.
// Это явно помечено флагом DemoMode.
package app

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
	"nis-core/internal/engine"
	"nis-core/internal/ledger"
	"nis-core/internal/oracle"
	"nis-core/internal/security"
)

// Config — конфигурация узла.
type Config struct {
	// NodeID — идентификатор узла в Zero Trust контуре.
	NodeID string `yaml:"node_id"`

	// DBPath — путь к директории BadgerDB.
	DBPath string `yaml:"db_path"`

	// APIAddr — адрес HTTP API узла (например, ":8080").
	APIAddr string `yaml:"api_addr"`

	// OracleURL — базовый URL сервиса-оракула Росреестра.
	// Пустая строка — узел работает offline, без обращения к оракулу.
	OracleURL string `yaml:"oracle_url"`

	// OracleTLS — настройки mTLS для соединения с оракулом.
	// Если Enabled=false, используется обычный HTTP.
	OracleTLS OracleTLSConf `yaml:"oracle_tls"`

	// Keys — ключевой материал.
	Keys KeysConfig `yaml:"keys"`

	// DemoMode разрешает держать приватные ключи обеих сторон
	// (эмитента и оракула) в одном процессе. Только для прототипа.
	DemoMode bool `yaml:"demo_mode"`
}

// KeysConfig — ключевой материал в hex-форме.
//
// Каждая роль (issuer, oracle) может быть описана одним из трёх
// способов, в порядке приоритета:
//  1. Приватный ключ (priv) — из него выводится публичный;
//  2. Публичный ключ (pub) — только для верификации;
//  3. GenerateIfMissing=true — сгенерировать пару (только в demo).
type KeysConfig struct {
	// Приватные ключи — только для demo-режима.
	IssuerPrivateHex string `yaml:"issuer_private_hex"`
	OraclePrivateHex string `yaml:"oracle_private_hex"`

	// Публичные ключи — для production-режима, когда узел
	// только верифицирует подписи удалённых сторон.
	IssuerPublicHex string `yaml:"issuer_public_hex"`
	OraclePublicHex string `yaml:"oracle_public_hex"`

	// MilitaryHashKeyHex — 32-байтный секретный ключ для HMAC-формирования
	// обезличенного идентификатора военнослужащего.
	// Пусто → сгенерировать (только в demo_mode).
	MilitaryHashKeyHex string `yaml:"military_hash_key_hex"`

	// Сгенерировать отсутствующие ключи. Только в DemoMode.
	GenerateIfMissing bool `yaml:"generate_if_missing"`
}

// OracleTLSConf — настройки mTLS-соединения узла с оракулом.
type OracleTLSConf struct {
	Enabled        bool   `yaml:"enabled"`
	CACertPath     string `yaml:"ca_cert_path"`
	ClientCertPath string `yaml:"client_cert_path"`
	ClientKeyPath  string `yaml:"client_key_path"`
}

// LoadConfig читает конфиг из YAML-файла.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("app: read config %q: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	// KnownFields(true) заставляет yaml-декодер вернуть ошибку при
	// встрече неизвестного ключа. Это ловит опечатки вроде `db_pth`.
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("app: parse config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate проверяет обязательные поля и подставляет дефолты.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("app: nil config")
	}
	if c.NodeID == "" {
		return fmt.Errorf("app: node_id is required")
	}
	if c.DBPath == "" {
		return fmt.Errorf("app: db_path is required")
	}
	if c.APIAddr == "" {
		c.APIAddr = ":8080"
	}
	if !c.DemoMode && c.Keys.GenerateIfMissing {
		return fmt.Errorf("app: keys.generate_if_missing allowed only in DemoMode")
	}
	// Для каждой роли должен быть хотя бы один источник ключа.
	if c.Keys.IssuerPrivateHex == "" &&
		c.Keys.IssuerPublicHex == "" &&
		!c.Keys.GenerateIfMissing {
		return fmt.Errorf(
			"app: provide issuer_private_hex, issuer_public_hex or generate_if_missing")
	}
	if c.Keys.OraclePrivateHex == "" &&
		c.Keys.OraclePublicHex == "" &&
		!c.Keys.GenerateIfMissing {
		return fmt.Errorf(
			"app: provide oracle_private_hex, oracle_public_hex or generate_if_missing")
	}
	return nil
}

// App — собранный узел.
type App struct {
	Config *Config

	Crypto  *crypto.GOSTProvider
	Ledger  *ledger.BadgerLedger
	Engine  *engine.SmartContractEngine
	Oracle  *oracle.Client // nil, если OracleURL не задан
	Gateway *security.ZeroTrustGateway

	MilitaryHashKey []byte

	// Публичные ключи доверенных сторон — всегда заполнены.
	IssuerPub *gost3410.PublicKey
	OraclePub *gost3410.PublicKey

	// Приватные ключи — заполнены, если заданы в конфиге
	// или сгенерированы в demo-режиме. Иначе nil.
	IssuerPriv *gost3410.PrivateKey
	OraclePriv *gost3410.PrivateKey
}

// New собирает узел из конфигурации.
func New(cfg *Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("app: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	g := crypto.NewGOSTProvider()
	gtw := security.NewZeroTrustGateway(g)
	generate := cfg.Keys.GenerateIfMissing && cfg.DemoMode

	issuerPriv, issuerPub, err := resolveKeypair(
		g,
		cfg.Keys.IssuerPrivateHex,
		cfg.Keys.IssuerPublicHex,
		generate,
		"issuer",
	)
	if err != nil {
		return nil, fmt.Errorf("app: issuer keys: %w", err)
	}

	oraclePriv, oraclePub, err := resolveKeypair(
		g,
		cfg.Keys.OraclePrivateHex,
		cfg.Keys.OraclePublicHex,
		generate,
		"oracle",
	)
	if err != nil {
		return nil, fmt.Errorf("app: oracle keys: %w", err)
	}

	bl, err := ledger.NewBadgerLedger(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("app: open ledger: %w", err)
	}

	milKey, err := resolveMilitaryHashKey(g, cfg.Keys.MilitaryHashKeyHex, generate)
	if err != nil {
		_ = bl.Close()
		return nil, fmt.Errorf("app: military hash key: %w", err)
	}

	eng, err := engine.NewSmartContractEngine(bl, g, issuerPub, oraclePub, milKey)
	if err != nil {
		_ = bl.Close()
		return nil, fmt.Errorf("app: new engine: %w", err)
	}

	a := &App{
		Config:          cfg,
		Crypto:          g,
		Ledger:          bl,
		Engine:          eng,
		IssuerPub:       issuerPub,
		OraclePub:       oraclePub,
		IssuerPriv:      issuerPriv,
		OraclePriv:      oraclePriv,
		MilitaryHashKey: milKey,
	}

	if cfg.OracleURL != "" {
		var oc *oracle.Client
		var err error
		if cfg.OracleTLS.Enabled {
			if cfg.OracleTLS.CACertPath == "" ||
				cfg.OracleTLS.ClientCertPath == "" ||
				cfg.OracleTLS.ClientKeyPath == "" {
				_ = a.Close()
				return nil, fmt.Errorf(
					"app: oracle_tls.enabled requires ca_cert_path, client_cert_path and client_key_path")
			}
			oc, err = oracle.NewMTLSClient(
				cfg.OracleURL,
				cfg.OracleTLS.CACertPath,
				cfg.OracleTLS.ClientCertPath,
				cfg.OracleTLS.ClientKeyPath,
			)
		} else {
			oc, err = oracle.NewClient(cfg.OracleURL, nil)
		}
		if err != nil {
			_ = a.Close()
			return nil, fmt.Errorf("app: oracle client: %w", err)
		}
		a.Oracle = oc
	}

	a.Gateway = gtw

	return a, nil
}

// Close освобождает ресурсы.
func (a *App) Close() error {
	if a == nil || a.Ledger == nil {
		return nil
	}
	return a.Ledger.Close()
}

// resolveKeypair восстанавливает ключи из hex или генерирует новые.
//
// Приоритет источников:
//  1. Приватный ключ (privHex) — из него выводится публичный.
//  2. Публичный ключ (pubHex) — только для верификации.
//  3. generate=true — сгенерировать новую пару.
//
// Приватный ключ может быть nil (read-only узел).
func resolveKeypair(
	g *crypto.GOSTProvider,
	privHex, pubHex string,
	generate bool,
	role string,
) (*gost3410.PrivateKey, *gost3410.PublicKey, error) {
	if privHex != "" {
		raw, err := hex.DecodeString(privHex)
		if err != nil {
			return nil, nil, fmt.Errorf("decode %s private hex: %w", role, err)
		}
		priv, err := g.NewPrivateKeyFromRaw(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s private: %w", role, err)
		}
		pub, err := priv.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("derive %s public: %w", role, err)
		}
		return priv, pub, nil
	}

	if pubHex != "" {
		raw, err := hex.DecodeString(pubHex)
		if err != nil {
			return nil, nil, fmt.Errorf("decode %s public hex: %w", role, err)
		}
		pub, err := g.NewPublicKeyFromRaw(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s public: %w", role, err)
		}
		return nil, pub, nil
	}

	if generate {
		priv, pub, err := g.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "[app] generated %s private: %s\n",
			role, hex.EncodeToString(priv.Raw()))
		fmt.Fprintf(os.Stderr, "[app] generated %s public : %s\n",
			role, hex.EncodeToString(pub.Raw()))
		return priv, pub, nil
	}

	return nil, nil, fmt.Errorf("no key material for %s", role)
}

// resolveMilitaryHashKey возвращает ключ HMAC для militaryHash.
//
// Приоритет источников:
//  1. hex-строка из конфига (32 байта).
//  2. generate=true → сгенерировать и вывести в stderr.
func resolveMilitaryHashKey(
	g *crypto.GOSTProvider,
	hexStr string,
	generate bool,
) ([]byte, error) {
	if hexStr != "" {
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("decode military_hash_key_hex: %w", err)
		}
		if len(raw) < 32 {
			return nil, errors.New("military_hash_key_hex must be at least 32 bytes")
		}
		return raw, nil
	}
	if !generate {
		return nil, errors.New("military_hash_key_hex required (or enable generate_if_missing in demo_mode)")
	}
	key, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "[app] generated military_hash_key: %s\n",
		hex.EncodeToString(key))
	return key, nil
}
