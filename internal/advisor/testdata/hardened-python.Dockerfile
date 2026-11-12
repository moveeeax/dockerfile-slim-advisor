# syntax=docker/dockerfile:1.7
# hardened-python — minimal, non-root base for pure-Python services.
#
# Runtime layer is gcr.io/distroless/python3: a CPython interpreter with no
# shell and no package manager. Pinned by digest; the :nonroot variant runs as
# uid 65532. Bring your dependencies as a wheel layer or a copied virtualenv;
# this example ships a stdlib-only app so the base stays dependency-free.
FROM gcr.io/distroless/python3-debian13@sha256:1c32c3720dc4c7f0c7dbe998737f32c200add6511eca7cec705008be488b87d6
LABEL org.opencontainers.image.title="hardened-python" \
      org.opencontainers.image.description="Minimal distroless base for Python services" \
      org.opencontainers.image.source="https://github.com/moveeeax/docker-hardened-base" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="gcr.io/distroless/python3-debian13:nonroot"
WORKDIR /app
COPY examples/python/app.py /app/app.py
# uid:gid 65532 (nonroot), enforced numerically for runAsNonRoot policies.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python3", "/app/app.py"]
