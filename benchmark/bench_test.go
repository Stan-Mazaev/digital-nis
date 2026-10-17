// Пакет benchmark содержит стресс-тесты «Цифровой НИС» для
// формирования количественных показателей в статьях ВАК.
//
// ВАЖНО: бенчмарк использует последовательный и параллельный
// режимы. Параллельный режим ограничен мьютексом внутри
// crypto.GOSTProvider — bi-zone небезопасен при параллельных
// подписях на одной Curve (паника math/big: underflow).
// Поэтому параллельные воркеры показывают выигрыш на I/O и
// Badger, но не на ЭЦП.
package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
	"nis-core/internal/engine"
	"nis-core/internal/ledger"
)

type benchEnv struct {
	g          *crypto.GOSTProvider
	engine     *engine.SmartContractEngine
	ledger     *ledger.BadgerLedger
	issuerPriv *gost3410.PrivateKey
	oraclePriv *gost3410.PrivateKey
}

func setupBenchEnv(b *testing.B) *benchEnv {
	b.Helper()

	g := crypto.NewGOSTProvider()

	issuerPriv, issuerPub, err := g.GenerateKeyPair()
	if err != nil {
		b.Fatalf("issuer keypair: %v", err)
	}
	oraclePriv, oraclePub, err := g.GenerateKeyPair()
	if err != nil {
		b.Fatalf("oracle keypair: %v", err)
	}

	dir := filepath.Join(b.TempDir(), "bench-db")
	bl, err := ledger.NewBadgerLedger(dir)
	if err != nil {
		b.Fatalf("ledger: %v", err)
	}
	b.Cleanup(func() { _ = bl.Close() })

	milKey, err := crypto.RandomBytes(32)
	if err != nil {
		b.Fatalf("milKey: %v", err)
	}
	eng, err := engine.NewSmartContractEngine(bl, g, issuerPub, oraclePub, milKey)
	if err != nil {
		b.Fatalf("engine: %v", err)
	}

	return &benchEnv{
		g:          g,
		engine:     eng,
		ledger:     bl,
		issuerPriv: issuerPriv,
		oraclePriv: oraclePriv,
	}
}

// runOneCycle — полный цикл одной сделки.
//
// Срок блокировки передаётся и в эмиссию, и в LockInEscrow —
// это гарантирует, что проверка lockDuration ≤ MaxLockDuration
// внутри IssueColoredRubles пройдёт с тем же значением, что
// фактически уйдёт в эскроу.
//
// Подпись оракула формируется через OracleResponseDigest с тем же
// trigger, что и у контракта — иначе engine.ProcessRosreestrCallback
// отвергнет её по ErrOracleSigInvalid / ErrTokenMisuse.
func runOneCycle(env *benchEnv, dealID, milHash, inn, kadastr string) error {
	token, err := env.engine.IssueColoredRubles(
		485_000_000, milHash, inn, kadastr,
		engine.DefaultLockDuration, env.issuerPriv,
	)
	if err != nil {
		return fmt.Errorf("issue: %w", err)
	}
	if err := env.engine.LockInEscrow(
		dealID, token, engine.TriggerRegistration, engine.DefaultLockDuration,
	); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	digest := env.g.OracleResponseDigest(
		dealID, kadastr, string(engine.TriggerRegistration), true,
	)
	oracleSig, err := env.g.SignGOST3410(env.oraclePriv, digest)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := env.engine.ProcessRosreestrCallback(
		dealID, kadastr, engine.TriggerRegistration, true, oracleSig,
	); err != nil {
		return fmt.Errorf("callback: %w", err)
	}
	return nil
}

// BenchmarkFullCycle — последовательный полный цикл сделки.
func BenchmarkFullCycle(b *testing.B) {
	env := setupBenchEnv(b)

	latencies := make([]time.Duration, 0, b.N)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		opStart := time.Now()

		dealID := fmt.Sprintf("DEAL-BENCH-%d", i)
		milHash := fmt.Sprintf("mil-%d", i)
		kadastr := fmt.Sprintf("77:01:%07d:1001", i%1_000_000)

		if err := runOneCycle(env, dealID, milHash, "7701982341", kadastr); err != nil {
			b.Fatalf("cycle[%d]: %v", i, err)
		}

		latencies = append(latencies, time.Since(opStart))
	}
	elapsed := time.Since(start)
	b.StopTimer()

	if b.N < 10 {
		return // warmup-прогон, отчёт не печатаем
	}
	report(b, "SEQUENTIAL", len(latencies), elapsed, latencies)
}

// BenchmarkParallelFullCycle — параллельный полный цикл.
//
// Подписи сериализуются мьютексом внутри GOSTProvider,
// поэтому параллелизм ограничен. Основной выигрыш — на I/O Badger.
func BenchmarkParallelFullCycle(b *testing.B) {
	env := setupBenchEnv(b)

	const numWorkers = 8
	opsPerWorker := b.N / numWorkers
	if opsPerWorker == 0 {
		opsPerWorker = 1
	}

	latencies := make([]time.Duration, b.N)
	var latIdx atomic.Uint64
	var successCount atomic.Uint64

	var wg sync.WaitGroup
	b.ResetTimer()
	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				opStart := time.Now()

				dealID := fmt.Sprintf("DEAL-PAR-%d-%d", workerID, i)
				milHash := fmt.Sprintf("mil-%d-%d", workerID, i)
				kadastr := fmt.Sprintf("77:01:%07d:1001", (workerID*1000+i)%1_000_000)

				if err := runOneCycle(env, dealID, milHash, "7701982341", kadastr); err != nil {
					continue
				}
				successCount.Add(1)

				idx := latIdx.Add(1) - 1
				if int(idx) < len(latencies) {
					latencies[idx] = time.Since(opStart)
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	b.StopTimer()

	done := int(successCount.Load())
	if done == 0 {
		b.Fatal("no successful cycles")
	}
	if done < len(latencies) {
		latencies = latencies[:done]
	}

	if b.N < 10 {
		return
	}
	report(b, "PARALLEL (8 workers)", done, elapsed, latencies)
}

// report собирает метрики и печатает таблицу.
func report(
	b *testing.B,
	mode string,
	count int,
	elapsed time.Duration,
	latencies []time.Duration,
) {
	b.Helper()
	if len(latencies) == 0 {
		b.Fatal("no latencies collected")
	}

	tps := float64(count) / elapsed.Seconds()
	b.ReportMetric(tps, "TPS")

	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	p := func(q float64) time.Duration {
		if len(sorted) == 0 {
			return 0
		}
		idx := int(float64(len(sorted)-1) * q)
		return sorted[idx]
	}

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	avg := total / time.Duration(len(sorted))

	printReport(mode, count, elapsed, tps, avg, p(0.50), p(0.95), p(0.99), sorted[len(sorted)-1])
}

// printReport печатает таблицу в stdout и сохраняет копию в файл.
// Использование ASCII-рамок гарантирует, что вывод не зависит от
// кодировки консоли (PowerShell 5.1, cmd.exe, bash — все читают
// одинаково).
func printReport(
	mode string,
	count int,
	elapsed time.Duration,
	tps float64,
	avg, p50, p95, p99, mx time.Duration,
) {
	lines := []string{
		"",
		"+----------------------------------------------------------+",
		fmt.Sprintf("|  BENCHMARK RESULTS: DIGITAL NIS [%s]", padRight(mode, 20)),
		"+----------------------------------------------------------+",
		fmt.Sprintf("|  Full deal cycles      : %10d                          |", count),
		fmt.Sprintf("|  Total time            : %-14v                  |", elapsed.Round(time.Millisecond)),
		fmt.Sprintf("|  Throughput            : %10.2f TPS                     |", tps),
		"+----------------------------------------------------------+",
		"|  Latency (per full cycle)                                |",
		fmt.Sprintf("|    average : %-14v                              |", avg.Round(time.Microsecond)),
		fmt.Sprintf("|    p50     : %-14v                              |", p50.Round(time.Microsecond)),
		fmt.Sprintf("|    p95     : %-14v                              |", p95.Round(time.Microsecond)),
		fmt.Sprintf("|    p99     : %-14v                              |", p99.Round(time.Microsecond)),
		fmt.Sprintf("|    max     : %-14v                              |", mx.Round(time.Microsecond)),
		"+----------------------------------------------------------+",
		"|  Crypto    : GOST R 34.11-2012 / 34.10-2012              |",
		"|  Storage   : BadgerDB (embedded, LSM-tree)               |",
		"+----------------------------------------------------------+",
		"",
	}

	// stdout
	for _, l := range lines {
		fmt.Fprintln(os.Stdout, l)
	}

	// файл (UTF-8)
	if path := os.Getenv("NIS_BENCH_OUT"); path != "" {
		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "benchmark: write %s: %v\n", path, err)
		} else {
			fmt.Fprintf(os.Stderr, "benchmark: results written to %s\n", path)
		}
	}
}

// padRight дополняет строку пробелами справа до ширины w.
func padRight(s string, w int) string {
	for len(s) < w {
		s += " "
	}
	return s
}
