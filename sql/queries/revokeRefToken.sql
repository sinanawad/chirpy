-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET updated_at = NOW(), revoked_at = NOW()
WHERE token = $1
RETURNING *;