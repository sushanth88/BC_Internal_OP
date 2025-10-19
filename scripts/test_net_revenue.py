from app import app, init_db, SessionLocal, User, Transaction
from werkzeug.security import generate_password_hash


def ensure_admin(db):
    admin = db.query(User).filter_by(username='__test_admin__').first()
    if not admin:
        admin = User(username='__test_admin__', password_hash=generate_password_hash('secret'), is_admin=True)
        db.add(admin)
        db.commit()
    return admin


def run_test():
    init_db()
    db = SessionLocal()
    admin = ensure_admin(db)

    client = app.test_client()
    # fetch login page to get CSRF token
    rv = client.get('/login')
    import re
    m = re.search(rb'name="csrf_token"\s+type="hidden"\s+value="([^"]+)"', rv.data)
    token = m.group(1).decode() if m else None
    # login
    rv = client.post('/login', data={'username': admin.username, 'password': 'secret', 'csrf_token': token}, follow_redirects=True)
    if b'Logged in successfully' not in rv.data:
        print('Login failed; response snippet:', rv.data[:200])
        return

    # build form data: party_orders_cash affects staff_commission, and fees affect net_revenue
    form = {
        'date': '2025-10-19',
        'number_of_orders': '5',
        'total_net_sale': '100.00',
        'net_card_tips': '10.00',
        'after_discount_cash': '20.00',
        'dining_cash_and_tips': '30.00',
        'dine_in_tips': '5.00',
        'party_orders_cash': '200.00',
        'biryani_po': '50.00',
        'event_hall': '0.00',
        'paid_to': '15.00',
        'grubhub': '0.00',
        'doordash': '0.00',
        'uber_eats': '0.00',
        'cancelled_orders': '0.00',
        # admin-only fees
        'toast_fees': '5.00',
        'doordash_fees': '2.00',
        'uber_eats_fees': '1.00',
        'grubhub_fees': '0.50',
        'notes': 'test',
    }

    # fetch new transaction form to get CSRF token
    rv = client.get('/transactions/new')
    m = re.search(rb'name="csrf_token"\s+type="hidden"\s+value="([^"]+)"', rv.data)
    token = m.group(1).decode() if m else None
    form['csrf_token'] = token
    rv = client.post('/transactions/new', data=form, follow_redirects=True)
    if rv.status_code != 200:
        print('Create POST failed, status:', rv.status_code)

    # fetch the transaction
    tx = db.query(Transaction).order_by(Transaction.created_at.desc()).first()
    print('Transaction id:', tx.id)
    print('Gross revenue:', tx.gross_revenue)
    print('Net revenue:', tx.net_revenue)
    print('Staff commission:', tx.staff_commission)


if __name__ == '__main__':
    run_test()
