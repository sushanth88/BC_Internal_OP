# Biryani City Portal (Flask)

Simple internal accounting app using Flask + SQLite. Two user roles: admin and regular.

Setup

1. Create a virtualenv and install requirements:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Initialize the database and create an admin:

```bash
flask --app app.py init-db
flask --app app.py create-admin
```

3. Run locally:

```bash
flask --app app.py run
```

Usage notes
- Regular users can create/edit today's transactions only.
- Admins can edit and view any historical transactions.

Next steps
- Add tests and more robust user management (registration, password reset).
- Add CSV export and reporting.

Navigation submenus
- To add a hover submenu to any nav item, wrap the parent link in a `.nav-item.has-submenu` div and add a `.submenu` with links.
- The submenu opens on hover/focus and on click/touch (JS toggles aria-expanded for accessibility).
- Utilities:
	- `.submenu.right` right-aligns the dropdown to the parent.
	- `.submenu.narrow` reduces min-width to 140px.

Deployment
Option A: Docker (simple)
- Build image:
  docker build -t biryani-portal:latest .
- Run container (bind host port 8000):
  docker run --rm -p 8000:8000 -e BC_SECRET="change-me" biryani-portal:latest
- Visit http://SERVER_IP:8000

Optionally, add a reverse proxy (Nginx/Caddy/Traefik) in front for TLS.

Option B: Bare metal with Gunicorn + Nginx (Ubuntu/Debian)
1) SSH to server and install deps:
	sudo apt update && sudo apt install -y python3-venv python3-pip nginx
2) Place app under /opt:
	sudo mkdir -p /opt/biryani-portal && sudo chown $USER:$USER /opt/biryani-portal
	rsync -av --exclude .venv ./ /opt/biryani-portal/
3) Create venv and install:
	cd /opt/biryani-portal && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt gunicorn
4) Set a secret and port:
	echo "export BC_SECRET=change-me" | sudo tee -a /etc/environment
5) Configure systemd:
	sudo cp deploy/systemd/biryani-portal.service /etc/systemd/system/
	sudo systemctl daemon-reload && sudo systemctl enable --now biryani-portal
6) Configure Nginx:
	sudo cp deploy/nginx/biryani-portal.conf /etc/nginx/sites-available/
	sudo ln -sf /etc/nginx/sites-available/biryani-portal.conf /etc/nginx/sites-enabled/
	sudo nginx -t && sudo systemctl reload nginx

Visit http://SERVER_IP to access. Add TLS via certbot if you have a domain.

SQLite note: The DB file lives at data.sqlite in the app directory. For servers, ensure the service user has read/write permissions, and back it up periodically. For multi-instance or higher concurrency, migrate to Postgres.
