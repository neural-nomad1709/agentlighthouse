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

# Base images and uv are pinned by digest (the tag is kept for readability).
# A tag can be moved; a digest cannot. Refresh with:
#   docker buildx imagetools inspect <image>:<tag>

# -- dashboard: Vite/React/TS -> static assets (frontend/) ---------------------
# The output is static files, so this stage always runs on the build host's
# own architecture, even in a multi-arch build.
FROM --platform=$BUILDPLATFORM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS dashboard

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
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build

COPY --from=ghcr.io/astral-sh/uv:0.11.29@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc /uv /uvx /bin/

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
    uv sync --frozen --no-dev --no-install-package agentlighthouse-governance

# -- core runtime: no dashboard ------------------------------------------------
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS core

# Non-root runtime user (least privilege — invariant #9).
RUN useradd --system --uid 10001 --home-dir /app --no-create-home al

WORKDIR /app
COPY --from=build /app /app
# Pre-create the volume mount points owned by the runtime user: a fresh named
# volume inherits this ownership (root-owned otherwise -> keygen/ledger
# EACCES, and the control plane could not write the kill-switch sentinel).
# /app/signing holds the data plane's private key on a volume the control
# plane never mounts. /app/killswitch and /app/approvals are the two things
# both planes write.
RUN mkdir -p /app/data /app/killswitch /app/signing /app/approvals && chown al:al /app/data /app/killswitch /app/signing /app/approvals
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
