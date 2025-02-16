-- name: UpdateRefreshToken :one
UPDATE refresh_tokens
SET updated_at = NOW()
WHERE token = $1
RETURNING *;