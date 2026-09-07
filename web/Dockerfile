# The web half of scope. It serves HTML and reads .cache/; it runs nothing from the toolkit.
#
# Deliberately thin. No docker CLI, no jq, no dig, no /var/run/docker.sock -- the host worker
# (web/worker.sh) owns execution, so this image has no way to run a scan even if something in it
# were persuaded to try.
FROM python:3.12-slim

# A non-root fallback for a bare `docker run`. In practice web/up.sh passes --user with the
# invoking user's uid, because the container and the host worker share one spool directory and
# have to agree on who owns a file.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin scope

WORKDIR /app/web
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER scope
EXPOSE 8787

# The repo is bind-mounted at /app at run time, so nothing is COPYied in: the code you are reading
# is the code that runs, and an edit needs a container restart rather than a rebuild.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8787", "--no-server-header"]
