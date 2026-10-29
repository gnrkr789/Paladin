FROM python:3.11-slim@sha256:0a19f628b6a9a96b0a0df9e0d3a327e8d51cd857804b04efcf1495879c97326b
# Debian packages come from a fixed snapshot (Release files are still signature-checked
# with the base image keyring) and exact versions, so rebuilds resolve the same packages.
ARG DEBIAN_SNAPSHOT=20261027T000000Z
RUN rm /etc/apt/sources.list.d/debian.sources \
    && for suite in debian/trixie debian/trixie-updates debian-security/trixie-security; do \
         echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/${suite%%/*}/$DEBIAN_SNAPSHOT ${suite#*/} main"; \
       done > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends strace=6.13+ds-1 git=1:2.47.3-0+deb13u1 mercurial=7.0.1-2 \
    && rm -rf /var/lib/apt/lists/*
RUN dpkg-query -W strace git mercurial mercurial-common git-man
RUN printf 'pip==23.2.1 --hash=sha256:7ccf472345f20d35bdc9d1841ff5f313260c2c33fe417f48c30ac46cccabf5be\n' > /tmp/pip-runtime.txt \
    && python -m pip install --no-cache-dir --no-deps --no-compile --require-hashes --target /opt/pip-runtime -r /tmp/pip-runtime.txt \
    && rm /tmp/pip-runtime.txt && chmod -R a-w /opt/pip-runtime
COPY observer.py target.py trace_grammar.py /opt/paladin/
RUN printf '[safe]\n\tdirectory = /fixtures/gitsource/.git\n' > /opt/paladin/gitconfig \
    && chmod 0444 /opt/paladin/gitconfig && chmod 0555 /opt/paladin /opt/paladin/*.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/work HGRCPATH=/dev/null HGPLAIN=1 GIT_CONFIG_NOSYSTEM=1
# Root-owned read-only Git fixture; local transport drops GIT_CONFIG_COUNT, so use a read-only global file.
ENV GIT_CONFIG_GLOBAL=/opt/paladin/gitconfig
ENTRYPOINT ["python", "-I", "/opt/paladin/observer.py"]
