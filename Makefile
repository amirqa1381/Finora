up:        ; docker compose up --build
test:      ; docker compose run --rm api pytest
lint:      ; ruff check . && mypy app
migrate:   ; docker compose run --rm api alembic upgrade head
revision:  ; docker compose run --rm api alembic revision --autogenerate -m "$(m)"
