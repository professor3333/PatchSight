# The offline pipeline's image: Python 3.12, the locked dependencies with every extra, and
# PatchSight itself. It holds no data, cache, key or third-party source. Mount a working
# copy for those, and pass secrets as environment variables at run time.
#
#   docker build -t patchsight-pipeline .
#   docker run --rm -v "$PWD":/work patchsight-pipeline reproduce --root /work
#
# Base images are pinned by digest; dependencies come from uv.lock.
FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b

COPY --from=ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH

WORKDIR /src
# Dependencies first, so a code change does not reinstall them.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --all-extras --no-dev --no-install-project
COPY LICENSE ./
COPY docs/pypi.md docs/pypi.md
COPY src src
RUN uv sync --locked --all-extras --no-dev --no-editable

RUN useradd --create-home --uid 10001 pipeline
USER pipeline
WORKDIR /work
ENTRYPOINT ["python", "-m", "patchsight.pipeline"]
CMD ["--help"]
