package duckdb

import (
	"context"
	"database/sql"

	"relay/internal/domain/admin"
)

func (r *Repository) GrantAdmin(ctx context.Context, a admin.Administrator) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admins (pubkey, label, granted_by, granted_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (pubkey) DO UPDATE SET label = excluded.label, granted_by = excluded.granted_by, granted_at = excluded.granted_at
	`, a.Pubkey, nullableString(a.Label), a.GrantedBy, a.GrantedAt)
	return err
}

func (r *Repository) RevokeAdmin(ctx context.Context, pubkey string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM admins WHERE pubkey = ?", pubkey)
	return err
}

func (r *Repository) ListAdmins(ctx context.Context) ([]admin.Administrator, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT pubkey, label, granted_by, granted_at FROM admins ORDER BY granted_at, pubkey")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	admins := []admin.Administrator{}
	for rows.Next() {
		var a admin.Administrator
		var label sql.NullString
		if err := rows.Scan(&a.Pubkey, &label, &a.GrantedBy, &a.GrantedAt); err != nil {
			return nil, err
		}
		a.Label = label.String
		admins = append(admins, a)
	}
	return admins, rows.Err()
}

// nullableString stores an empty label as NULL, matching how an omitted
// moderation reason reads back.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
