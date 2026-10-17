package main

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter — простой in-memory лимитер по IP.
//
// Использует token bucket: у каждого IP есть бакет, из которого
// на каждый запрос списывается один токен. Токены пополняются
// с фиксированной скоростью.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	// capacity — максимальное число токенов в бакете.
	capacity float64
	// refillPerSecond — сколько токенов добавляется в секунду.
	refillPerSecond float64

	now func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewRateLimiter создаёт лимитер.
//
// capacity — сколько запросов можно сделать «пачкой»;
// refillPerSecond — с какой скоростью токены восстанавливаются.
//
// Пример: capacity=100, refillPerSecond=100.0/60 = ~1.67 токена/сек
// эквивалентно «100 запросов в минуту».
func NewRateLimiter(capacity, refillPerSecond float64) *rateLimiter {
	return &rateLimiter{
		buckets:         make(map[string]*bucket),
		capacity:        capacity,
		refillPerSecond: refillPerSecond,
		now:             time.Now,
	}
}

// Allow проверяет, разрешён ли запрос от указанного ключа.
func (rl *rateLimiter) Allow(key string) bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.capacity, lastSeen: now}
		rl.buckets[key] = b
	}

	// Пополняем бакет.
	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.refillPerSecond
		if b.tokens > rl.capacity {
			b.tokens = rl.capacity
		}
		b.lastSeen = now
	}

	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

// evictOlderThan удаляет записи, к которым давно не обращались.
// Вызывается вручную или по крону, чтобы не копить мусор в памяти.
func (rl *rateLimiter) evictOlderThan(d time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := rl.now().Add(-d)
	for k, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}

// clientIP извлекает IP клиента из запроса.
//
// Учитывает X-Forwarded-For, X-Real-IP (если узел за прокси).
// В противном случае — RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Первый адрес в списке — исходный клиент.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitMiddleware оборачивает handler проверкой лимита по IP.
func rateLimitMiddleware(rl *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.Allow(clientIP(r)) {
				w.Header().Set("Retry-After", "1")
				writeErr(w, http.StatusTooManyRequests,
					errors.New("rate limit exceeded"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
