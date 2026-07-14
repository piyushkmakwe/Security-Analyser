# Getting a link to use the tool

The scanner runs a small **web server** — the checks (reading a site's HTTP
headers, inspecting its TLS certificate) can only run server-side, not inside a
browser. So "getting a link" means running that server somewhere. Pick whichever
option fits you.

---

## Option A — Just use it on your own computer (fastest, free, private)

```bash
pip install -e .
security-analyser serve
```

Open **http://127.0.0.1:8000** in your browser. Done. Nothing is exposed to the
internet; only you can reach it. This is the recommended way for personal use.

---

## Option B — A temporary public link (share it for a few hours)

Run it locally (Option A), then in a second terminal open a tunnel:

```bash
# Using cloudflared (no signup):
cloudflared tunnel --url http://localhost:8000

# ...or ngrok:
ngrok http 8000
```

Either prints a public `https://…` URL that forwards to your local server.
The link lives only while that command is running.

---

## Option C — A permanent hosted link (Render, free tier)

This repo includes a `Dockerfile` and `render.yaml` blueprint.

1. Make sure the repo is on GitHub (it is).
2. Go to <https://dashboard.render.com/select-repo?type=blueprint> and select
   this repository.
3. Render reads `render.yaml`, builds the `Dockerfile`, and gives you a
   permanent `https://security-analyser-xxxx.onrender.com` URL.

The same image runs anywhere that takes a Dockerfile (Railway, Fly.io, Google
Cloud Run, a VM, etc.):

```bash
docker build -t security-analyser .
docker run -p 8000:8000 security-analyser
# → http://localhost:8000
```

The server reads the `PORT` and `HOST` environment variables, so it works on
platforms that inject a port.

---

## ⚠️ Important if you host it publicly (Options B & C)

A public instance is an **open scanner**: anyone who finds the URL can make your
server send requests to any site they type. To avoid your host being used to
probe others:

- Prefer **Option A** (local) for day-to-day use.
- If you host it, put it behind authentication (a login proxy, Cloudflare
  Access, HTTP basic auth) or keep the URL private and short-lived.
- Don't leave a public instance running longer than you need it.
