import os
from datetime import date, datetime

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm, CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import (create_engine, Column, Integer, String, Date, Float, Text, Boolean, DateTime, ForeignKey, UniqueConstraint)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, scoped_session
from sqlalchemy import text
from wtforms import StringField, PasswordField, SubmitField, BooleanField, FloatField, IntegerField, DateField, TextAreaField
from wtforms.validators import DataRequired, Length
from sqlalchemy.exc import IntegrityError

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'data.sqlite')
SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_PATH}'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('BC_SECRET', 'dev-secret')

# enable CSRF protection for forms and POST endpoints
csrf = CSRFProtect()
csrf.init_app(app)

engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=False, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    transactions = relationship('Transaction', back_populates='user')
    # when Transaction has multiple FKs to users (user_id, last_edited_by),
    # explicitly bind this relationship to the creator FK
    transactions = relationship('Transaction', back_populates='user', foreign_keys='Transaction.user_id')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @classmethod
    def create(cls, username, password, is_admin=False):
        return cls(username=username, password_hash=generate_password_hash(password), is_admin=is_admin)


class Transaction(Base):
    __tablename__ = 'transactions'
    # enforce uniqueness per date (only one transaction row per date globally)
    __table_args__ = (UniqueConstraint('date', name='uix_date'),)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    date = Column(Date, nullable=False)

    total_net_sale = Column(Float, default=0.0)
    # number of orders (display above total_net_sale in form)
    number_of_orders = Column(Integer, default=0)
    net_card_tips = Column(Float, default=0.0)
    voids_cash_sale = Column(Float, default=0.0)
    after_discount_cash = Column(Float, default=0.0)
    dining_cash_and_tips = Column(Float, default=0.0)
    # tips collected for dine-in separate from dine-in cash
    dine_in_tips = Column(Float, default=0.0)
    party_orders_cash = Column(Float, default=0.0)
    biryani_po = Column(Float, default=0.0)
    event_hall = Column(Float, default=0.0)
    paid_to = Column(Float, default=0.0)
    total_cash = Column(Float, default=0.0)
    grubhub = Column(Float, default=0.0)
    doordash = Column(Float, default=0.0)
    uber_eats = Column(Float, default=0.0)
    cancelled_orders = Column(Float, default=0.0)
    # free-form notes field
    gross_revenue = Column(Float, default=0.0)
    notes = Column(Text, default='')
    # admin-only financial fields
    staff_commission = Column(Float, default=0.0)
    toast_fees = Column(Float, default=0.0)
    doordash_fees = Column(Float, default=0.0)
    uber_eats_fees = Column(Float, default=0.0)
    grubhub_fees = Column(Float, default=0.0)
    net_revenue = Column(Float, default=0.0)
    cash_verified_by_owner = Column(String(200), default='')

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # track who last edited this transaction (user id)
    last_edited_by = Column(Integer, ForeignKey('users.id'), nullable=True)

    last_edited_user = relationship('User', foreign_keys=[last_edited_by])

    # explicitly bind the creator relationship to the user_id FK
    user = relationship('User', back_populates='transactions', foreign_keys=[user_id])


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action = Column(String(50), nullable=False)  # create/edit/delete
    tx_id = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(Text, default='')

    # bind actor relationship to actor_id FK to avoid ambiguity
    actor = relationship('User', foreign_keys=[actor_id])


@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    return db.get(User, int(user_id))


@app.context_processor
def inject_today_tx():
    # expose whether the current logged-in user already has a transaction for today
    try:
        if not current_user.is_authenticated:
            return dict(today_tx_exists=False, today_tx_id=None)
        db = SessionLocal()
        # since transactions are unique per date globally, check existence by date
        exists = db.query(Transaction).filter(Transaction.date==date.today()).first()
        return dict(today_tx_exists=bool(exists), today_tx_id=(exists.id if exists else None))
    except Exception:
        return dict(today_tx_exists=False, today_tx_id=None)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class TransactionForm(FlaskForm):
    date = DateField('Date', default=date.today(), validators=[DataRequired()])
    number_of_orders = IntegerField('Number of Orders', default=0)
    total_net_sale = FloatField('Total Voids', default=0.0)
    net_card_tips = FloatField('Net Card Tips', default=0.0)
    voids_cash_sale = FloatField('Voids Cash Sale (After 5% Discount)', default=0.0)
    after_discount_cash = FloatField('Toast Card Sale', default=0.0)
    dining_cash_and_tips = FloatField('Dine-In Cash', default=0.0)
    dine_in_tips = FloatField('Dine-In Tips', default=0.0)
    party_orders_cash = FloatField('Catering Orders (Exclude Biryani Trays)', default=0.0)
    biryani_po = FloatField('Biryani Trays', default=0.0)
    event_hall = FloatField('Event Hall Rental & Food', default=0.0)
    paid_to = FloatField('Paid to Employee (Add Name in Notes)', default=0.0)
    total_cash = FloatField('Total Cash', default=0.0)
    grubhub = FloatField('Grubhub', default=0.0)
    doordash = FloatField('Doordash', default=0.0)
    uber_eats = FloatField('Uber Eats', default=0.0)
    cancelled_orders = FloatField('Cancelled Orders', default=0.0)
    gross_revenue = FloatField('Gross Revenue', default=0.0)
    # Admin-only fields
    staff_commission = FloatField('Staff Commission', default=0.0)
    toast_fees = FloatField('Toast Fees', default=0.0)
    doordash_fees = FloatField('Doordash Fees', default=0.0)
    uber_eats_fees = FloatField('Uber Eats Fees', default=0.0)
    grubhub_fees = FloatField('Grubhub Fees', default=0.0)
    net_revenue = FloatField('Net Revenue', default=0.0)
    cash_verified_by_owner = StringField('Cash Verified By Owner', default='')
    notes = TextAreaField('Notes', default='')
    submit = SubmitField('Save')


def init_db():
    Base.metadata.create_all(bind=engine)
    # Deduplicate existing transactions: keep the earliest created_at per date (global)
    with engine.begin() as conn:
        # Add last_edited_by column if missing (SQLite allows simple ADD COLUMN)
        try:
            conn.execute(text("SELECT last_edited_by FROM transactions LIMIT 1"))
        except Exception:
            # column missing -> add it
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN last_edited_by INTEGER'))
            except Exception:
                pass
        # Add new columns if missing: number_of_orders, dine_in_tips, notes
        try:
            conn.execute(text("SELECT number_of_orders FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN number_of_orders INTEGER DEFAULT 0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT dine_in_tips FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN dine_in_tips REAL DEFAULT 0.0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT notes FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE transactions ADD COLUMN notes TEXT DEFAULT ''"))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT gross_revenue FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN gross_revenue REAL DEFAULT 0.0'))
            except Exception:
                pass
        # admin-only fields migration
        try:
            conn.execute(text("SELECT staff_commission FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN staff_commission REAL DEFAULT 0.0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT toast_fees FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN toast_fees REAL DEFAULT 0.0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT doordash_fees FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN doordash_fees REAL DEFAULT 0.0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT uber_eats_fees FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN uber_eats_fees REAL DEFAULT 0.0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT grubhub_fees FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN grubhub_fees REAL DEFAULT 0.0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT net_revenue FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN net_revenue REAL DEFAULT 0.0'))
            except Exception:
                pass
        try:
            conn.execute(text("SELECT cash_verified_by_owner FROM transactions LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE transactions ADD COLUMN cash_verified_by_owner VARCHAR(200) DEFAULT ''"))
            except Exception:
                pass
        # If there was a previous unique index on (user_id, date), drop it
        conn.execute(text('DROP INDEX IF EXISTS uix_user_date'))
        # find groups with duplicates by date
        dup_rows = conn.execute(text("SELECT date, COUNT(*) AS cnt FROM transactions GROUP BY date HAVING COUNT(*)>1")).fetchall()
        for row in dup_rows:
            d = row[0]
            # select ids ordered by created_at ascending
            id_rows = conn.execute(text("SELECT id FROM transactions WHERE date=:d ORDER BY created_at ASC"), {'d': d}).fetchall()
            ids = [r[0] for r in id_rows]
            # keep first, delete others
            if len(ids) > 1:
                del_ids = ids[1:]
                id_list_sql = ','.join(str(int(x)) for x in del_ids)
                if id_list_sql:
                    conn.execute(text(f"DELETE FROM transactions WHERE id IN ({id_list_sql})"))
        # Now create unique index on date (will succeed since duplicates removed)
        conn.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS uix_date ON transactions(date)'))


# Run migrations at import time to ensure the schema includes newly added columns.
try:
    init_db()
except Exception:
    # ignore migration errors at import time; runtime queries will surface issues
    pass


@app.route('/')
@login_required
def index():
    db = SessionLocal()
    if current_user.is_admin:
        txs = db.query(Transaction).order_by(Transaction.date.desc()).limit(100).all()
    else:
        # regular users see only today's transaction (global)
        today = date.today()
        txs = db.query(Transaction).filter(Transaction.date == today).all()
    # pass today's date so template can decide whether regular users may edit
    return render_template('index.html', transactions=txs, today=date.today())


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db = SessionLocal()
        user = db.query(User).filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('login'))


def can_edit_tx(tx: Transaction):
    # admin can edit any transaction. Regular users can edit only the transaction for today's date (global).
    if current_user.is_admin:
        return True
    return tx.date == date.today()


@app.route('/transactions/new', methods=['GET', 'POST'])
@login_required
def new_transaction():
    form = TransactionForm()
    db = SessionLocal()
    # If GET and today's transaction exists for this user, redirect to edit it.
    if request.method == 'GET':
        check_date = date.today()
        # since transactions are unique per date globally, check for any transaction for today
        exists_today = db.query(Transaction).filter(Transaction.date==check_date).first()
        if exists_today:
            flash('A transaction for today already exists. Redirecting to edit.', 'info')
            return redirect(url_for('edit_transaction', tx_id=exists_today.id))

    if form.validate_on_submit():
        # all users may only create for today
        if form.date.data != date.today():
            flash('Transactions may only be created for today.', 'warning')
            return redirect(url_for('new_transaction'))
        # enforce only one transaction per date (global)
        exists = db.query(Transaction).filter(Transaction.date==form.date.data).first()
        if exists:
            flash('A transaction for this date already exists. Edit the existing transaction instead.', 'warning')
            return redirect(url_for('edit_transaction', tx_id=exists.id))
        # compute derived values server-side
        paid_to_val = float(form.paid_to.data or 0.0)
        # Voids Cash Sale is computed as Total Voids * 0.95 (after 5% discount) and cannot be set by the client
        total_net_sale_val = float(form.total_net_sale.data or 0.0)
        voids = float(total_net_sale_val * 0.95)
        dineCash = float(form.dining_cash_and_tips.data or 0.0)
        dineTips = float(form.dine_in_tips.data or 0.0)
        party = float(form.party_orders_cash.data or 0.0)
        biryani = float(form.biryani_po.data or 0.0)
        eventHall = float(form.event_hall.data or 0.0)
        total_cash_val = voids + dineCash + dineTips + party + biryani + eventHall - paid_to_val

        afterDiscount = float(form.after_discount_cash.data or 0.0)
        netCard = float(form.net_card_tips.data or 0.0)
        doordash_val = float(form.doordash.data or 0.0)
        uber = float(form.uber_eats.data or 0.0)
        grub = float(form.grubhub.data or 0.0)
        cancelled = float(form.cancelled_orders.data or 0.0)
        gross_val = total_cash_val + (afterDiscount + netCard + doordash_val + uber + grub) - cancelled

        toastFeesVal = float(form.toast_fees.data or 0.0)
        doordashFeesVal = float(form.doordash_fees.data or 0.0)
        uberFeesVal = float(form.uber_eats_fees.data or 0.0)
        grubFeesVal = float(form.grubhub_fees.data or 0.0)
        net_val = gross_val - (toastFeesVal + doordashFeesVal + uberFeesVal + grubFeesVal)

        # compute staff commission as 10% of Catering Orders (party_orders_cash) and enforce server-side
        staff_commission_val = float((form.party_orders_cash.data or 0.0) * 0.10)

        tx = Transaction(
            user_id=current_user.id,
            date=form.date.data,
            total_net_sale=form.total_net_sale.data or 0.0,
            number_of_orders=form.number_of_orders.data or 0,
            net_card_tips=form.net_card_tips.data or 0.0,
            # enforce server-side voids value
            voids_cash_sale=voids,
            after_discount_cash=form.after_discount_cash.data or 0.0,
            dining_cash_and_tips=form.dining_cash_and_tips.data or 0.0,
            dine_in_tips=form.dine_in_tips.data or 0.0,
            party_orders_cash=form.party_orders_cash.data or 0.0,
            biryani_po=form.biryani_po.data or 0.0,
            event_hall=form.event_hall.data or 0.0,
            paid_to=paid_to_val,
            total_cash=total_cash_val,
            grubhub=form.grubhub.data or 0.0,
            doordash=form.doordash.data or 0.0,
            uber_eats=form.uber_eats.data or 0.0,
            cancelled_orders=form.cancelled_orders.data or 0.0,
            gross_revenue=gross_val,
            # admin-only financial fields: staff_commission is computed as 10% of party_orders_cash and cannot be posted
            staff_commission=staff_commission_val,
            toast_fees=(form.toast_fees.data or 0.0) if current_user.is_admin else 0.0,
            doordash_fees=(form.doordash_fees.data or 0.0) if current_user.is_admin else 0.0,
            uber_eats_fees=(form.uber_eats_fees.data or 0.0) if current_user.is_admin else 0.0,
            grubhub_fees=(form.grubhub_fees.data or 0.0) if current_user.is_admin else 0.0,
            # net_revenue is computed server-side and authoritative
            net_revenue=net_val,
            cash_verified_by_owner=(form.cash_verified_by_owner.data or '') if current_user.is_admin else '',
            notes=form.notes.data or '',
        )
        tx.last_edited_by = current_user.id
        db.add(tx)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            # check by date globally
            existing = db.query(Transaction).filter(Transaction.date==tx.date).first()
            if existing:
                flash('A transaction for this date was just created. Redirecting to edit.', 'warning')
                return redirect(url_for('edit_transaction', tx_id=existing.id))
            flash('Could not save transaction due to a database error.', 'danger')
            return redirect(url_for('index'))
        # audit
        log = AuditLog(actor_id=current_user.id, action='create', tx_id=tx.id, details=f'Created transaction for {tx.date} by user {current_user.username}; last_edited_by={current_user.username}')
        db.add(log)
        db.commit()
        flash('Transaction saved', 'success')
        return redirect(url_for('index'))
    return render_template('transaction_form.html', form=form, action='New')


@app.route('/transactions/<int:tx_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_transaction(tx_id):
    db = SessionLocal()
    tx = db.get(Transaction, tx_id)
    if not tx:
        abort(404)
    if not can_edit_tx(tx):
        flash('You do not have permission to edit this transaction.', 'danger')
        return redirect(url_for('index'))
    form = TransactionForm(obj=tx)
    if form.validate_on_submit():
        if not current_user.is_admin and form.date.data != date.today():
            flash('Regular users may only set date to today.', 'warning')
            return redirect(url_for('edit_transaction', tx_id=tx_id))
        # Prevent changing the date to one that would duplicate another transaction for the same user
        db = SessionLocal()
        conflict = db.query(Transaction).filter(Transaction.user_id == tx.user_id, Transaction.date == form.date.data, Transaction.id != tx.id).first()
        if conflict:
            flash('Cannot change date — another transaction for this user already exists on that date.', 'warning')
            return redirect(url_for('edit_transaction', tx_id=tx_id))

        # update fields
        old = {f:getattr(tx,f) for f in ['date','number_of_orders','total_net_sale','net_card_tips','voids_cash_sale','after_discount_cash','dining_cash_and_tips','dine_in_tips','party_orders_cash','biryani_po','event_hall','paid_to','total_cash','grubhub','doordash','uber_eats','cancelled_orders','gross_revenue','staff_commission','toast_fees','doordash_fees','uber_eats_fees','grubhub_fees','net_revenue','cash_verified_by_owner','notes']}
        # set basic fields from form for non-computed and non-admin fields
        # We'll overwrite computed fields server-side below. Also, ignore admin-only fields for non-admin users.
        for field in ['date','number_of_orders','total_net_sale','net_card_tips','after_discount_cash','dining_cash_and_tips','dine_in_tips','party_orders_cash','biryani_po','event_hall','paid_to','grubhub','doordash','uber_eats','cancelled_orders','notes']:
            setattr(tx, field, getattr(form, field).data)
        # recompute derived values (server-side)
        paid_to_val = float(form.paid_to.data or 0.0)
        # Voids Cash Sale computed from total_net_sale
        total_net_sale_val = float(form.total_net_sale.data or 0.0)
        voids = float(total_net_sale_val * 0.95)
        dineCash = float(form.dining_cash_and_tips.data or 0.0)
        dineTips = float(form.dine_in_tips.data or 0.0)
        party = float(form.party_orders_cash.data or 0.0)
        biryani = float(form.biryani_po.data or 0.0)
        eventHall = float(form.event_hall.data or 0.0)
        total_cash_val = voids + dineCash + dineTips + party + biryani + eventHall - paid_to_val
        tx.total_cash = total_cash_val

        afterDiscount = float(form.after_discount_cash.data or 0.0)
        netCard = float(form.net_card_tips.data or 0.0)
        doordash_val = float(form.doordash.data or 0.0)
        uber = float(form.uber_eats.data or 0.0)
        grub = float(form.grubhub.data or 0.0)
        cancelled = float(form.cancelled_orders.data or 0.0)
        gross_val = total_cash_val + (afterDiscount + netCard + doordash_val + uber + grub) - cancelled
        tx.gross_revenue = gross_val

        toastFeesVal = float(form.toast_fees.data or 0.0)
        doordashFeesVal = float(form.doordash_fees.data or 0.0)
        uberFeesVal = float(form.uber_eats_fees.data or 0.0)
        grubFeesVal = float(form.grubhub_fees.data or 0.0)
        net_val = gross_val - (toastFeesVal + doordashFeesVal + uberFeesVal + grubFeesVal)
        # compute staff commission as 10% of Catering Orders (party_orders_cash) and enforce server-side
        staff_commission_val = float((form.party_orders_cash.data or 0.0) * 0.10)
        # admin-only fields: only overwrite with posted values if current_user is admin
        if current_user.is_admin:
            tx.staff_commission = staff_commission_val
            tx.toast_fees = form.toast_fees.data or 0.0
            tx.doordash_fees = form.doordash_fees.data or 0.0
            tx.uber_eats_fees = form.uber_eats_fees.data or 0.0
            tx.grubhub_fees = form.grubhub_fees.data or 0.0
            # net_revenue remains computed server-side for consistency
            tx.net_revenue = net_val
            tx.cash_verified_by_owner = form.cash_verified_by_owner.data or ''
        else:
            # ensure non-admins cannot set admin fields; staff_commission is still computed
            tx.staff_commission = staff_commission_val
            tx.toast_fees = 0.0
            tx.doordash_fees = 0.0
            tx.uber_eats_fees = 0.0
            tx.grubhub_fees = 0.0
            tx.net_revenue = net_val
            tx.cash_verified_by_owner = ''
        tx.last_edited_by = current_user.id
        db.add(tx)
        db.commit()
        # audit
        changes = []
        for k,v in old.items():
            if getattr(tx,k) != v:
                changes.append(f'{k}: {v} -> {getattr(tx,k)}')
        log = AuditLog(actor_id=current_user.id, action='edit', tx_id=tx.id, details='; '.join(changes) or 'no changes')
        db.add(log)
        db.commit()
        flash('Transaction updated', 'success')
        return redirect(url_for('index'))
    return render_template('transaction_form.html', form=form, action='Edit')


@app.route('/transactions/<int:tx_id>/delete', methods=['POST'])
@login_required
def delete_transaction(tx_id):
    db = SessionLocal()
    tx = db.get(Transaction, tx_id)
    if not tx:
        abort(404)
    if not can_edit_tx(tx):
        flash('You do not have permission to delete this transaction.', 'danger')
        return redirect(url_for('index'))
    db.delete(tx)
    db.commit()
    # audit
    log = AuditLog(actor_id=current_user.id, action='delete', tx_id=tx_id, details=f'Deleted transaction {tx_id}')
    db.add(log)
    db.commit()
    flash('Transaction deleted', 'info')
    return redirect(url_for('index'))


@app.route('/admin/audit-logs')
@login_required
def audit_logs():
    if not current_user.is_admin:
        abort(403)
    db = SessionLocal()
    # filters
    page = int(request.args.get('page', 1))
    per_page = 50
    action = request.args.get('action')
    actor = request.args.get('actor')

    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if actor:
        # try matching username
        actor_user = db.query(User).filter(User.username == actor).first()
        if actor_user:
            q = q.filter(AuditLog.actor_id == actor_user.id)
    total = q.count()
    logs = q.order_by(AuditLog.timestamp.desc()).offset((page-1)*per_page).limit(per_page).all()
    has_next = (page*per_page) < total
    has_prev = page > 1
    return render_template('audit_logs.html', logs=logs, page=page, has_next=has_next, has_prev=has_prev, action=action or '', actor=actor or '')


@app.cli.command('init-db')
def cli_init_db():
    """Initialize the database."""
    init_db()
    print('Initialized DB at', DB_PATH)


@app.cli.command('create-admin')
def cli_create_admin():
    """Create an admin user interactively."""
    init_db()
    db = SessionLocal()
    username = input('Admin username: ')
    password = input('Password: ')
    if db.query(User).filter_by(username=username).first():
        print('User exists')
        return
    admin = User.create(username=username, password=password, is_admin=True)
    db.add(admin)
    db.commit()
    print('Admin created')


if __name__ == '__main__':
    init_db()
    # prefer explicit port 50010 to avoid macOS services binding to 5000
    import sys
    port = 50010
    # allow overriding via command-line --port or FLASK_RUN_PORT env
    for i, a in enumerate(sys.argv):
        if a == '--port' and i+1 < len(sys.argv):
            try:
                port = int(sys.argv[i+1])
            except Exception:
                pass
    port = int(os.environ.get('FLASK_RUN_PORT', port))
    app.run(debug=True, port=port)
