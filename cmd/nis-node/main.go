// Основной узел платформы «Цифровая НИС».
//
// Режимы работы:
//   - обычный: поднимает HTTP API, ждёт входящих запросов;
//   - -demo:   прогоняет сквозной сценарий (эмиссия → блокировка
//     → ответ оракула → released) и завершается.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nis-core/internal/app"
	"nis-core/internal/engine"
	"nis-core/internal/oracle"
	"nis-core/internal/security"
)

func main() {
	configPath := flag.String("config", "configs/node-smolensk.yaml", "path to YAML config")
	demo := flag.Bool("demo", false, "run end-to-end demo scenario and exit")
	apiOverride := flag.String("api", "", "override api_addr")
	flag.Parse()

	cfg, err := app.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[nis-node] %v", err)
	}
	if *apiOverride != "" {
		cfg.APIAddr = *apiOverride
	}

	a, err := app.New(cfg)
	if err != nil {
		log.Fatalf("[nis-node] %v", err)
	}
	defer a.Close()

	log.Printf("[nis-node] started: node_id=%s db=%s demo_mode=%v api=%s",
		cfg.NodeID, cfg.DBPath, cfg.DemoMode, cfg.APIAddr)

	if *demo {
		if err := runDemo(a); err != nil {
			log.Fatalf("[nis-node] demo: %v", err)
		}
		return
	}

	if err := runServer(a); err != nil {
		log.Fatalf("[nis-node] server: %v", err)
	}
}

// runDemo прогоняет сквозной сценарий.
//
// Если в конфиге задан oracle_url — узел действительно вызывает
// оракул по HTTP, и ответ приходит с настоящей ГОСТ-подписью.
// Если нет — узел подписывает ответ локально ключом из demo_mode.
//
// Срок эмиссии совпадает со сроком блокировки (engine.DefaultLockDuration),
// чтобы проверка lockDuration ≤ MaxLockDuration внутри IssueColoredRubles
// прошла с тем же значением, что уходит ниже в LockInEscrow.
//
// Триггер demo-сценария — REGISTRATION (готовое жильё): регистрация
// права собственности покупателя. Для сценария 214-ФЗ (RVE) узел
// должен запускаться с другим триггером — см. LockInEscrow ниже.
func runDemo(a *app.App) error {
	if !a.Config.DemoMode {
		return errors.New("demo requires demo_mode: true in config")
	}

	const (
		inn     = "7701982341"
		kadastr = "77:01:0001001:102"
		milHash = "mil-hash-demo"
		amount  = uint64(485_000_000)
	)

	trigger := engine.TriggerRegistration

	// Каждый прогон demo создаёт новую сделку, чтобы можно было
	// запускать сценарий многократно на одной и той же БД.
	dealID := fmt.Sprintf("DEAL-DEMO-%d", time.Now().Unix())

	fmt.Println("========== ДЕМО-СЦЕНАРИЙ «ЦИФРОВАЯ НИС» ==========")

	// 1. Эмиссия.
	log.Printf("[demo] 1/5 issue: amount=%d kop, inn=%s, kadastr=%s",
		amount, inn, kadastr)
	token, err := a.Engine.IssueColoredRubles(
		amount, milHash, inn, kadastr,
		engine.DefaultLockDuration, a.IssuerPriv,
	)
	if err != nil {
		return fmt.Errorf("issue: %w", err)
	}
	log.Printf("[demo]     token_id=%s... color_tag=%s...",
		prefix(token.TokenID, 16), prefix(token.TargetColorTag, 16))

	// 2. Блокировка.
	log.Printf("[demo] 2/5 lock in escrow: deal=%s trigger=%s timeout=%v",
		dealID, trigger, engine.DefaultLockDuration)
	if err := a.Engine.LockInEscrow(
		dealID, token, trigger, engine.DefaultLockDuration,
	); err != nil {
		return fmt.Errorf("lock: %w", err)
	}

	// 3. Получаем подпись оракула на success=true.
	log.Printf("[demo] 3/5 obtain oracle signature (success=true)")
	var oracleSig []byte
	if a.Oracle != nil {
		log.Printf("[demo]     calling oracle over HTTP: %s", a.Config.OracleURL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := a.Oracle.Register(ctx, &oracle.RegisterRequest{
			DealID:  dealID,
			Kadastr: kadastr,
			Trigger: string(trigger),
		})
		if err != nil {
			return fmt.Errorf("oracle call: %w", err)
		}
		if !resp.Success {
			return errors.New("oracle rejected registration")
		}
		oracleSig = resp.Signature
	} else {
		log.Printf("[demo]     oracle_url not set, signing locally with demo key")
		digest := a.Crypto.OracleResponseDigest(
			dealID, kadastr, string(trigger), true,
		)
		oracleSig, err = a.Crypto.SignGOST3410(a.OraclePriv, digest)
		if err != nil {
			return fmt.Errorf("sign oracle: %w", err)
		}
	}
	log.Printf("[demo]     signature=%d bytes", len(oracleSig))

	// 4. Обрабатываем колбэк.
	log.Printf("[demo] 4/5 process rosreestr callback")
	if err := a.Engine.ProcessRosreestrCallback(
		dealID, kadastr, trigger, true, oracleSig,
	); err != nil {
		return fmt.Errorf("callback: %w", err)
	}

	// 5. Читаем финальное состояние.
	log.Printf("[demo] 5/5 read final state")
	c, err := a.Engine.GetEscrow(dealID)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	fmt.Println("=================================================")
	fmt.Printf("  Статус контракта : %s\n", c.Status)
	fmt.Printf("  DealID           : %s\n", c.DealID)
	fmt.Printf("  Триггер          : %s\n", c.Trigger)
	fmt.Printf("  Сумма            : %d kop (%.2f руб)\n", c.Token.Amount, float64(c.Token.Amount)/100)
	fmt.Printf("  Кадастр          : %s\n", c.Token.CadastralNumber)
	fmt.Printf("  Settlement TX    : %s\n", prefix(c.SettlementTxID, 24))
	fmt.Printf("  Создан           : %s\n", time.Unix(c.CreatedAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("  Обновлён         : %s\n", time.Unix(c.UpdatedAt, 0).UTC().Format(time.RFC3339))
	fmt.Println("=================================================")
	return nil
}

func runServer(a *app.App) error {
	h := &handlers{app: a}

	// Лимитер: 100 запросов в минуту на IP, восстанавливается по 100/60 в секунду.
	rl := NewRateLimiter(100, 100.0/60.0)
	limitMW := rateLimitMiddleware(rl)

	// Фоновая очистка старых записей лимитера раз в 10 минут.
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-t.C:
				rl.evictOlderThan(30 * time.Minute)
			}
		}
	}()

	mux := http.NewServeMux()

	// Открытые эндпоинты.
	mux.HandleFunc("/healthz", h.healthz)

	// Защищённые эндпоинты с проверкой ролей и rate limiting.
	mux.Handle("/api/v1/issue",
		limitMW(requireRoles(a, security.RoleEmitter, security.RoleAdmin)(http.HandlerFunc(h.issue))))
	mux.Handle("/api/v1/lock",
		limitMW(requireRoles(a, security.RoleUser, security.RoleAdmin)(http.HandlerFunc(h.lock))))
	mux.Handle("/api/v1/rosreestr/callback",
		limitMW(requireRoles(a, security.RoleOracle, security.RoleAdmin)(http.HandlerFunc(h.rosreestrCallback))))
	mux.Handle("/api/v1/demo/run",
		limitMW(requireRoles(a, security.RoleAdmin)(http.HandlerFunc(h.demoRun))))
	mux.Handle("/api/v1/security/status",
		limitMW(requireRoles(a, security.RoleAuditor, security.RoleAdmin)(http.HandlerFunc(h.securityStatus))))
	mux.Handle("/api/v1/escrow/",
		limitMW(requireRoles(a, security.RoleUser, security.RoleAuditor, security.RoleAdmin)(http.HandlerFunc(h.getEscrow))))

	srv := &http.Server{
		Addr:              a.Config.APIAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Контекст для фоновых воркеров.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	// Фоновый обработчик автовозврата по истечении тайм-лока.
	go startRefundWorker(workerCtx, a, time.Hour)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("[nis-node] HTTP API listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[nis-node] listen: %v", err)
		}
	}()

	<-stop
	log.Println("[nis-node] shutdown signal received")

	// Останавливаем воркеры.
	workerCancel()
	cleanupCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// startRefundWorker запускает фоновую обработку истёкших тайм-локов.
//
// Раз в interval проходит по всем контрактам в статусе
// LOCKED_IN_ESCROW и вызывает RefundExpired для тех, у которых
// истёк срок. Завершается при отмене контекста.
func startRefundWorker(ctx context.Context, a *app.App, interval time.Duration) {
	log.Printf("[refund] worker started, interval=%v", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[refund] worker stopped")
			return
		case <-ticker.C:
			runRefundCycle(a)
		}
	}
}

// runRefundCycle выполняет один проход по реестру.
//
// Сначала собирает список dealID в статусе Locked, затем для каждого
// вызывает RefundExpired. Двухфазный проход нужен, потому что
// BadgerDB не позволяет писать в базу, пока открыт итератор.
func runRefundCycle(a *app.App) {
	var locked []string
	err := a.Ledger.IterateEscrows(func(dealID string, c *engine.EscrowContract) error {
		if c.Status == engine.StatusLocked {
			locked = append(locked, dealID)
		}
		return nil
	})
	if err != nil {
		log.Printf("[refund] iterate failed: %v", err)
		return
	}
	if len(locked) == 0 {
		return
	}

	log.Printf("[refund] checking %d locked contracts", len(locked))
	refunded := 0
	for _, dealID := range locked {
		err := a.Engine.RefundExpired(dealID)
		if err == nil {
			refunded++
			log.Printf("[refund] contract %s refunded", dealID)
			continue
		}
		// ErrContractExpired означает, что тайм-лок ещё не истёк —
		// это нормальное состояние, не логируем.
		if errors.Is(err, engine.ErrContractExpired) {
			continue
		}
		log.Printf("[refund] %s: %v", dealID, err)
	}
	if refunded > 0 {
		log.Printf("[refund] cycle done, refunded=%d", refunded)
	}
}

// prefix возвращает первые n символов строки. Безопасно для коротких строк.
func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
