isort:
    uvx isort --length-sort --profile black --line-length 120 Evtx/ tests/ evtx_scripts/

black:
    uvx black --line-length 120 Evtx/ tests/ evtx_scripts/

ruff:
    uvx ruff check --line-length 120 Evtx/ tests/ evtx_scripts/

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports Evtx/ tests/ evtx_scripts/

lint:
    -just isort
    -just black
    -just ruff
    # this doesn't pass cleanly today
    #-just mypy

test:
    uv run pytest tests/
