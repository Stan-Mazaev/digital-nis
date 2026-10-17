#!/usr/bin/env bash
# Генерация тестовых пар ключей ГОСТ Р 34.10-2012 для узла и оракула.
#
# ВНИМАНИЕ: скрипт генерирует НЕСЕРТИФИЦИРОВАННЫЕ ключи для локальной
# отладки и тестов. В промышленной эксплуатации ключи должны
# генерироваться и храниться в сертифицированном HSM (КриптоПро,
# ViPNet). Никогда не используйте эти ключи в реальной системе.
#
# Скрипт вызывает временную Go-программу, которая генерирует пару
# через тот же crypto.GOSTProvider, что используется в проекте.

set -euo pipefail

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/gen.go" <<'EOF'
package main

import (
	"encoding/hex"
	"fmt"

	"nis-core/internal/crypto"
)

func main() {
	g := crypto.NewGOSTProvider()

	for _, role := range []string{"issuer", "oracle"} {
		priv, pub, err := g.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s_private_hex: %s\n", role, hex.EncodeToString(priv.Raw()))
		fmt.Printf("%s_public_hex:  %s\n", role, hex.EncodeToString(pub.Raw()))
		fmt.Println()
	}
}
EOF

echo "==> Генерация тестовых ключей ГОСТ Р 34.10-2012"
echo ""

# Запускаем через `go run`, но в контексте корневого модуля.
cd "$(dirname "$0")/.."
go run "${TMP_DIR}/gen.go"

echo ""
echo "==> Скопируйте полученные значения в configs/*.yaml."
echo "==> НЕ коммитьте приватные ключи в git!"
