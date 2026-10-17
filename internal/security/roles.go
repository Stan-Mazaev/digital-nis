package security

// Роли участников системы.
const (
	RoleEmitter = "emitter" // Росвоенипотека — эмитент ЦР
	RoleOracle  = "oracle"  // Росреестр — оракул
	RoleUser    = "user"    // военнослужащий
	RoleAuditor = "auditor" // ФСБ / ЦБ
	RoleAdmin   = "admin"   // администратор узла
)

// IsValidRole проверяет, что строка соответствует известной роли.
func IsValidRole(r string) bool {
	switch r {
	case RoleEmitter, RoleOracle, RoleUser, RoleAuditor, RoleAdmin:
		return true
	}
	return false
}
