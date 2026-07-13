FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Accept external connections when running in a container / on a host.
# PORT is read at runtime (many platforms, e.g. Render, inject it).
ENV HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

CMD ["security-analyser", "serve"]
