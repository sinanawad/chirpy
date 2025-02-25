// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: getuserbyemail.sql

package database

import (
	"context"
)

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, email, hashed_password, is_chirpy_red, created_at, updated_at FROM users WHERE email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
