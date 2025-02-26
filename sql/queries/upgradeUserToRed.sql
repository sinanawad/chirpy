-- name: UpgradeUserToRed :one
UPDATE users
SET is_chirpy_red = $1,
    updated_at = NOW()
WHERE id = $2
RETURNING *;
