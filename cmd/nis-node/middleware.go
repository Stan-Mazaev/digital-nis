package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"nis-core/internal/app"
	"nis-core/internal/security"
)

// Ключи для контекста запроса.
type ctxKey string

const (
	ctxRoleKey       ctxKey = "nis.role"
	ctxNodeIDKey     ctxKey = "nis.nodeID"
	ctxMilitaryIDKey ctxKey = "nis.militaryID"
)

// requireRoles оборачивает handler и допускает только указанные роли.
//
// Роль определяется из Zero Trust конверта (заголовок X-NIS-Envelope),
// либо — в demo-режиме — из заголовка X-NIS-Demo-Role.
func requireRoles(a *app.App, roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Читаем тело, чтобы посчитать payload hash, и возвращаем его назад.
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))

			role, nodeID, err := resolveRole(a, r, body)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, err)
				return
			}
			if _, ok := allowed[role]; !ok {
				writeErr(w, http.StatusForbidden,
					fmt.Errorf("security: role %q not allowed for this endpoint", role))
				return
			}

			ctx := context.WithValue(r.Context(), ctxRoleKey, role)
			ctx = context.WithValue(ctx, ctxNodeIDKey, nodeID)
			// В demo-режиме militaryHash может прийти в заголовке.
			if mh := r.Header.Get("X-NIS-Military-Hash"); mh != "" {
				ctx = context.WithValue(ctx, ctxMilitaryIDKey, mh)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveRole определяет роль запроса.
//
// Приоритет:
//  1. Zero Trust конверт из заголовка X-NIS-Envelope.
//  2. В demo-режиме — заголовок X-NIS-Demo-Role (по умолчанию admin).
func resolveRole(a *app.App, r *http.Request, body []byte) (string, string, error) {
	if raw := r.Header.Get("X-NIS-Envelope"); raw != "" {
		if a.Gateway == nil {
			return "", "", errors.New("security: gateway not configured")
		}
		envBytes, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", "", fmt.Errorf("security: bad envelope base64: %w", err)
		}
		var env security.ZeroTrustEnvelope
		if err := json.Unmarshal(envBytes, &env); err != nil {
			return "", "", fmt.Errorf("security: bad envelope json: %w", err)
		}
		auth, err := a.Gateway.AuthorizeRequest(&env, body)
		if err != nil {
			return "", "", err
		}
		return auth.Role, auth.NodeID, nil
	}

	if a.Config.DemoMode {
		role := r.Header.Get("X-NIS-Demo-Role")
		if role == "" {
			role = security.RoleAdmin
		}
		if !security.IsValidRole(role) {
			return "", "", fmt.Errorf("security: invalid demo role %q", role)
		}
		return role, "demo-client", nil
	}

	return "", "", errors.New("security: missing Zero Trust envelope")
}

// roleFromContext возвращает роль, установленную middleware.
func roleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRoleKey).(string); ok {
		return v
	}
	return ""
}

// militaryIDFromContext возвращает militaryHash из заголовка (demo).
func militaryIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxMilitaryIDKey).(string); ok {
		return v
	}
	return ""
}
