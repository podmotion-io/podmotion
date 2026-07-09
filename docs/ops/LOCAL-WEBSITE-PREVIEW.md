# Local Website Preview

Standing capability, stood up 2026-07-03. A static export of the marketing
website (sibling repo at `../website`, i.e.
`/home/chad/Desktop/projects/podmotion/website` on the dev server) is built
and served locally via nginx in Docker, independent of the GitHub Pages
deployment described in `website/README.md`.

This is for previewing site changes on the LAN before they're pushed live.
It is not part of the CI/CD deploy pipeline (`.github/workflows/deploy.yml`
in the website repo still owns the real `podmotion.io` publish to
`gh-pages`).

## Start / stop

```bash
cd /home/chad/Desktop/projects/podmotion/website
npm run build              # produces the static export in ./out
sudo docker compose up -d  # starts nginx:alpine serving ./out
```

Stop with:

```bash
cd /home/chad/Desktop/projects/podmotion/website
sudo docker compose down
```

Rebuild after content changes: repeat `npm run build`, then
`sudo docker compose up -d` again (nginx will pick up the new `./out`
contents; no restart needed since it's a live-mounted volume, but restarting
is harmless if the container's cache seems stale).

## Where it lives

- `website/docker-compose.yml` defines a single `preview` service:
  image `nginx:alpine`, mounts `./out` read-only to
  `/usr/share/nginx/html`, publishes host port **80**, `restart:
  unless-stopped` (survives reboots and Docker daemon restarts).
- Verified running: `sudo docker compose -f
  /home/chad/Desktop/projects/podmotion/website/docker-compose.yml ps` and
  `curl http://localhost/` (expect `200`).

## Access

- From the dev server itself or the LAN: `http://192.168.8.246/`
- From Chad's Mac: same address works now; `http://podmotion.local/` will
  also work once Chad adds a `192.168.8.246 podmotion.local` entry to his
  Mac's `/etc/hosts` — that step is manual and has not been done yet as of
  this writing.

Note: `website/preview.sh` is a pre-existing script but describes a
different, WSL-oriented dev workflow (port 3000, `docker compose` without
`sudo`, assumes a Windows/WSL host). It predates this Docker Compose
preview capability and was not used or updated for this setup — flagged
here so a future session doesn't assume `preview.sh` is the current
mechanism for the Linux dev server. It may be worth reconciling the two at
some point, but that's a separate task.

## Known incomplete: placeholder component

`website/app/page.tsx` imports a component for a planned marketing section
that did not exist and blocked the `npm run build` step above. A minimal,
honest placeholder component was written to unblock the build — it is not
real content. Designing the actual section is still an open item for Chad;
do not treat the placeholder as final copy.
