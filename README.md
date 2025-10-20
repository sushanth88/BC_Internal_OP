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
