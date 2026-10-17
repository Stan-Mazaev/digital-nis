# Makefile для проекта «Цифровая НИС».
#
# Работает в Linux, macOS и WSL. На чистом Windows используйте
# команды из блока "Windows equivalents" в README.md.
#
# Для сборки под Astra Linux SE «Смоленск» используйте цель `astra`.
# Для отладки в VS Code используйте launch.json (см. .vscode/).

SHELL := /bin/bash

# ------------------------------------------------------------------
# Переменные
# ------------------------------------------------------------------
APP_NODE     := nis-node
APP_ORACLE   := oracle-rosreestr
APP_AUDITOR  := auditor-cli
BUILD_DIR    := ./bin

GO           := go
GOFLAGS      :=
LDFLAGS      := -w -s

# Конфиги по умолчанию
CONFIG_NODE   := ./configs/node-smolensk.yaml
CONFIG_ORACLE := ./configs/oracle-mock.yaml

# Бенчмарк
BENCH_TIME_SEQ := 500x
BENCH_TIME_PAR := 200x

# ------------------------------------------------------------------
# Phony
# ------------------------------------------------------------------
.PHONY: all build build-node build-oracle build-auditor \
        test test-crypto test-engine test-ledger test-security test-oracle test-app \
        bench bench-seq bench-par \
        run-node run-oracle audit demo \
        fmt vet lint tidy clean help \
        astra astra-all

all: tidy fmt vet test build

# ------------------------------------------------------------------
# Сборка
# ------------------------------------------------------------------

build: build-node build-oracle build-auditor
	@echo "==> Сборка завершена, артефакты в $(BUILD_DIR)/"

build-node:
	@echo "==> Сборка $(APP_NODE)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_NODE) ./cmd/nis-node

build-oracle:
	@echo "==> Сборка $(APP_ORACLE)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_ORACLE) ./cmd/oracle-rosreestr

build-auditor:
	@echo "==> Сборка $(APP_AUDITOR)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_AUDITOR) ./cmd/auditor-cli

# Статическая сборка под Astra Linux SE «Смоленск».
# CGO отключён, бинарники не зависят от libc.
astra: astra-all

astra-all:
	@echo "==> Статическая сборка под Astra Linux (CGO_ENABLED=0)"
	@mkdir -p $(BUILD_DIR)/astra
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
	    -a -ldflags '-extldflags "-static" $(LDFLAGS)' \
	    -o $(BUILD_DIR)/astra/$(APP_NODE) ./cmd/nis-node
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
	    -a -ldflags '-extldflags "-static" $(LDFLAGS)' \
	    -o $(BUILD_DIR)/astra/$(APP_ORACLE) ./cmd/oracle-rosreestr
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
	    -a -ldflags '-extldflags "-static" $(LDFLAGS)' \
	    -o $(BUILD_DIR)/astra/$(APP_AUDITOR) ./cmd/auditor-cli
	@echo "==> Артефакты для Astra в $(BUILD_DIR)/astra/"

# ------------------------------------------------------------------
# Тесты
# ------------------------------------------------------------------

test:
	@echo "==> Запуск полного набора тестов"
	$(GO) test ./...

test-crypto:
	$(GO) test ./internal/crypto/... -v

test-engine:
	$(GO) test ./internal/engine/... -v

test-ledger:
	$(GO) test ./internal/ledger/... -v

test-security:
	$(GO) test ./internal/security/... -v

test-oracle:
	$(GO) test ./internal/oracle/... -v

test-app:
	$(GO) test ./internal/app/... -v

# ------------------------------------------------------------------
# Бенчмарки (для статьи ВАК)
# ------------------------------------------------------------------

bench: bench-seq bench-par
	@echo "==> Результаты:"
	@echo "    - results-sequential.txt"
	@echo "    - results-parallel.txt"

bench-seq:
	@echo "==> Последовательный бенчмарк ($(BENCH_TIME_SEQ))"
	NIS_BENCH_OUT=results-sequential.txt \
	    $(GO) test ./benchmark -bench=BenchmarkFullCycle \
	    -benchtime=$(BENCH_TIME_SEQ) -run=^$$ -v

bench-par:
	@echo "==> Параллельный бенчмарк ($(BENCH_TIME_PAR))"
	NIS_BENCH_OUT=results-parallel.txt \
	    $(GO) test ./benchmark -bench=BenchmarkParallelFullCycle \
	    -benchtime=$(BENCH_TIME_PAR) -run=^$$ -v

# ------------------------------------------------------------------
# Запуск сервисов
# ------------------------------------------------------------------

run-node: build-node
	$(BUILD_DIR)/$(APP_NODE) -config $(CONFIG_NODE)

run-oracle: build-oracle
	$(BUILD_DIR)/$(APP_ORACLE) -config $(CONFIG_ORACLE)

demo: build
	@echo "==> Демонстрационный сценарий (офлайн, без оракула)"
	$(BUILD_DIR)/$(APP_NODE) -config $(CONFIG_NODE) -demo

audit: build-auditor
	$(BUILD_DIR)/$(APP_AUDITOR) -db ./data/nis-state -cmd full-audit

# ------------------------------------------------------------------
# Качество кода
# ------------------------------------------------------------------

fmt:
	@echo "==> go fmt"
	$(GO) fmt ./...

vet:
	@echo "==> go vet"
	$(GO) vet ./...

tidy:
	@echo "==> go mod tidy"
	$(GO) mod tidy

lint:
	@echo "==> golangci-lint (требуется установка)"
	golangci-lint run ./...

# ------------------------------------------------------------------
# Очистка
# ------------------------------------------------------------------

clean:
	@echo "==> Очистка артефактов и данных"
	rm -rf $(BUILD_DIR)
	rm -rf ./data
	rm -f results-*.txt

# ------------------------------------------------------------------
# Справка
# ------------------------------------------------------------------

help:
	@echo "Доступные цели Makefile:"
	@echo ""
	@echo "  Сборка:"
	@echo "    make build            — собрать все бинарники в ./bin/"
	@echo "    make astra            — статическая сборка под Astra Linux"
	@echo "    make clean            — удалить bin/, data/, отчёты"
	@echo ""
	@echo "  Тесты:"
	@echo "    make test             — полный набор тестов"
	@echo "    make test-crypto      — только криптография"
	@echo "    make test-engine      — только ядро смарт-контрактов"
	@echo ""
	@echo "  Бенчмарки (ВАК):"
	@echo "    make bench            — оба бенчмарка, результаты в файлы"
	@echo "    make bench-seq        — только последовательный"
	@echo "    make bench-par        — только параллельный"
	@echo ""
	@echo "  Запуск:"
	@echo "    make run-node         — узел в серверном режиме (:8080)"
	@echo "    make run-oracle       — оракул-эмулятор (:8081)"
	@echo "    make demo             — demo-сценарий (офлайн)"
	@echo "    make audit            — полный аудит реестра"
	@echo ""
	@echo "  Качество кода:"
	@echo "    make fmt vet tidy     — стандартные проверки"
	@echo "    make all              — tidy + fmt + vet + test + build"