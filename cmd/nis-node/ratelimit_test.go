package main

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderCapacity(t *testing.T) {
	rl := NewRateLimiter(5, 1)
	for i := 0; i < 5; i++ {
		if !rl.Allow("ip-1") {
			t.Fatalf("request %d denied", i)
		}
	}
}

func TestRateLimiter_DeniesOverCapacity(t *testing.T) {
	rl := NewRateLimiter(3, 0) // без пополнения
	for i := 0; i < 3; i++ {
		rl.Allow("ip-1")
	}
	if rl.Allow("ip-1") {
		t.Fatal("expected denial")
	}
}

func TestRateLimiter_DifferentKeysIndependent(t *testing.T) {
	rl := NewRateLimiter(2, 0)
	rl.Allow("ip-1")
	rl.Allow("ip-1")
	// ip-1 исчерпан, но ip-2 ещё свежий.
	if !rl.Allow("ip-2") {
		t.Fatal("ip-2 should be allowed")
	}
}

func TestRateLimiter_Refill(t *testing.T) {
	rl := NewRateLimiter(2, 100) // очень быстрый refill
	now := time.Unix(0, 0)
	rl.now = func() time.Time { return now }

	rl.Allow("ip-1")
	rl.Allow("ip-1")
	if rl.Allow("ip-1") {
		t.Fatal("should be denied after exhausting")
	}

	// Продвигаем время на 1 секунду — пополнится 100 токенов (ограничено capacity=2).
	now = now.Add(1 * time.Second)
	if !rl.Allow("ip-1") {
		t.Fatal("should be allowed after refill")
	}
}

func TestRateLimiter_Evict(t *testing.T) {
	rl := NewRateLimiter(5, 1)
	now := time.Unix(1_000_000, 0)
	rl.now = func() time.Time { return now }

	rl.Allow("ip-old")
	rl.Allow("ip-new")

	// Продвигаем время на час, добавляем нового.
	now = now.Add(time.Hour)
	rl.Allow("ip-new-2")

	rl.evictOlderThan(30 * time.Minute)

	// ip-old должен быть удалён.
	rl.mu.Lock()
	_, oldExists := rl.buckets["ip-old"]
	rl.mu.Unlock()
	if oldExists {
		t.Fatal("ip-old should be evicted")
	}
}
