-- name: GetOneChirp :one
SELECT * FROM chirps WHERE id = $1;
