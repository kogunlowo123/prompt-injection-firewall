# A container that runs the firewall and can reproduce its own numbers.
#
# Two stages. The builder resolves the locked dependency set and installs the
# project into a self-contained virtual environment; the runtime copies that
# environment and the source, and carries no build tooling.

FROM python:3.12-slim-bookworm AS builder

# uv comes from its own published image rather than a curl-to-shell: the digest
# is pinned by the tag, and there is no download step that can quietly change.
COPY --from=ghcr.io/astral-sh/uv:0.9.9 /uv /usr/local/bin/uv

# Without this, `uv sync` creates .venv relative to the working directory and
# the runtime stage has to guess where it went.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /build

# Dependencies first, in their own layer: they change far less often than the
# source, and `--no-install-project` is what keeps the two separable.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-install-project --no-dev

COPY src ./src
COPY examples ./examples
COPY scripts ./scripts
COPY tasks.py tasks_local.py ./

# `--no-editable` installs a real copy into the environment. An editable install
# leaves a .pth file pointing at /build, which does not exist in the runtime
# stage, and the failure is an ImportError at container start.
RUN uv sync --locked --no-dev --no-editable


FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="prompt-injection-firewall" \
      org.opencontainers.image.description="A prompt-injection firewall that publishes its own bypass rate." \
      org.opencontainers.image.source="https://github.com/kogunlowo123/prompt-injection-firewall" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# A non-root user with no login shell and no home directory to write into.
# Nothing in this image needs to write anywhere except a bind-mounted record
# path, and that is the operator's to provide.
RUN groupadd --system --gid 10001 pifw \
 && useradd --system --uid 10001 --gid pifw --no-create-home --shell /usr/sbin/nologin pifw

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/examples /app/examples
COPY --from=builder /build/scripts /app/scripts
COPY --chown=pifw:pifw LICENSE README.md /app/

# `var/` is where the audit record and any scratch space go. Created here so a
# bind mount onto it inherits a directory that already exists, and made
# world-writable because a bind-mounted host directory arrives owned by whoever
# owns it on the host, which is not this uid.
RUN mkdir -p /app/var && chmod 0777 /app/var

USER pifw

HEALTHCHECK --interval=30s --timeout=20s --start-period=5s --retries=3 \
    CMD ["pifw", "doctor"]

# Naming a subcommand rather than leaving the entrypoint bare: `docker run
# <image>` should do something useful and self-describing, and `doctor` proves
# the installation works end to end in about a second.
ENTRYPOINT ["pifw"]
CMD ["doctor"]
