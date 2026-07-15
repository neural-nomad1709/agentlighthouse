# AgentLighthouse image (multi-stage: npm for the dashboard, uv for Python).
# Runs non-root; the hardened runtime baseline is enforced in docker-compose.yml.
# MIT-licensed throughout (see NOTICE).
#
# Two targets:
#
#   --target core   the Python core only (core/ verify/ spec/). No dashboard.
#   (default)       core + the fleet dashboard, prebuilt.
#
# The default ships the dashboard so `docker build .` alone yields a working
# /dashboard — a clone of the repo is sufficient to deploy, with no Node on the
# host. The governance layer (governance/, `al-gov`) is excluded from both:
# core never imports it and it runs on the control host.

# -- dashboard: Vite/React/TS -> static assets (frontend/) ---------------------
FROM node:20-slim AS dashboard

WORKDIR /frontend
# Playwright is a devDependency (e2e only); its browsers are useless to a build.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Dependencies first (cached) from the lockfile alone. Dev deps are REQUIRED:
# vite, tsc and @vitejs/plugin-react are what perform the build.
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY frontend/ ./
RUN npm run build   # tsc -b && vite build -> /frontend/dist (base=/dashboard/)

# -- python deps + workspace source (the core) ---------------------------------
FROM python:3.12-slim AS build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Install dependencies first (cached) using only the manifests.
COPY pyproject.toml uv.lock ./
COPY core/pyproject.toml core/pyproject.toml
COPY verify/pyproject.toml verify/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-workspace --no-dev

# Now install the workspace source. The governance layer is a workspace
# member but is deliberately neither copied nor installed here (core never
# imports it; `al-gov` runs on the control host). Skipping the install is what
# lets the frozen sync succeed without the governance/ sources present.
COPY core/ core/
COPY verify/ verify/
COPY spec/ spec/
COPY configs/ configs/
COPY policies/ policies/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-package al-governance

# -- core runtime: no dashboard ------------------------------------------------
FROM python:3.12-slim AS core

# Non-root runtime user (least privilege — invariant #9).
RUN useradd --system --uid 10001 --home-dir /app --no-create-home al

WORKDIR /app
COPY --from=build /app /app
# Pre-create the data + kill-switch dirs owned by the runtime user: a fresh
# named volume inherits this ownership (root-owned otherwise -> keygen/ledger
# EACCES, and the control plane could not write the kill-switch sentinel).
RUN mkdir -p /app/data /app/killswitch && chown al:al /app/data /app/killswitch
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

USER al
EXPOSE 8888
ENTRYPOINT ["al"]
CMD ["run", "--host", "0.0.0.0", "--port", "8888", "--config", "configs/balanced.yaml"]

# -- default runtime: core + the prebuilt fleet dashboard ----------------------
FROM core AS runtime

# al_core.app serves this tree at /dashboard (it resolves <repo root>/frontend/
# dist, which is /app/frontend/dist here). Left root-owned and read-only: the
# runtime user (al) serves these assets but must never be able to rewrite them.
COPY --from=dashboard /frontend/dist /app/frontend/dist
