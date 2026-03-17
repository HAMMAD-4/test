from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import make_url
import os
import secrets

app = Flask(__name__)
is_debug = os.environ.get('FLASK_DEBUG') == '1'
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if is_debug:
        secret_key = secrets.token_hex(32)
        app.logger.warning(
            'SECRET_KEY not set; using an ephemeral key. Sessions will not persist across restarts.'
        )
    else:
        raise RuntimeError('SECRET_KEY environment variable must be set')
app.config['SECRET_KEY'] = secret_key

# Database Configuration
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    database_url = 'sqlite:///app.db'
elif database_url.startswith('mysql://'):
    database_url = database_url.replace('mysql://', 'mysql+mysqlconnector://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

def ensure_database_exists(database_url_value):
    try:
        url = make_url(database_url_value)
    except Exception as exc:
        app.logger.warning('Unable to parse DATABASE_URL; skipping database creation: %s', exc)
        return
    if url.get_backend_name() != 'mysql' or not url.database:
        return
    db_name = url.database
    # Hyphens are supported because we always use dialect-quoted identifiers.
    if not all(char.isalnum() or char in {'_', '-'} for char in db_name):
        app.logger.warning('Skipping database creation due to invalid name: %s', db_name)
        return
    engine = None
    try:
        engine = create_engine(url.set(database=None))
        with engine.connect() as connection:
            quoted_db_name = engine.dialect.identifier_preparer.quote(db_name)
            connection.exec_driver_sql(f'CREATE DATABASE IF NOT EXISTS {quoted_db_name}')
    except SQLAlchemyError as exc:
        app.logger.warning('Unable to ensure database exists: %s', exc)
    finally:
        if engine is not None:
            engine.dispose()

ensure_database_exists(database_url)

db = SQLAlchemy(app)

# ─── MODELS ────────────────────────────────────────────────────────────────────

class Admin(db.Model):
    __tablename__ = 'admins'
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(50), unique=True, nullable=False)
    password   = db.Column(db.String(255), nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    cnic       = db.Column(db.String(20), nullable=False)
    email      = db.Column(db.String(100), nullable=False)
    phone      = db.Column(db.String(20), nullable=True)
    role       = db.Column(db.String(50), nullable=False, default='User')
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deleted_at = db.Column(db.DateTime, nullable=True)

class Service(db.Model):
    __tablename__ = 'services'
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    category    = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    poc_name    = db.Column(db.String(100), nullable=False)
    poc_email   = db.Column(db.String(100), nullable=False)
    poc_phone   = db.Column(db.String(30), nullable=False)
    is_deleted  = db.Column(db.Boolean, default=False, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

# Keep aligned with User.phone (String(20)).
PHONE_COLUMN_SQL = 'ALTER TABLE users ADD COLUMN phone VARCHAR(20) NULL'

# ─── DB INIT & SEED ────────────────────────────────────────────────────────────

DEFAULT_SERVICES = [
    {
        'name': 'Cloud Infrastructure',
        'category': 'Cloud',
        'description': 'Scalable AWS / Azure cloud hosting, auto-scaling groups, load balancers and 99.9% SLA. Includes managed Kubernetes clusters, VPC setup, and 24/7 monitoring dashboards.',
        'poc_name': 'Sarah Mitchell',
        'poc_email': 'sarah.mitchell@cloudops.io',
        'poc_phone': '+1 (415) 555-0192',
    },
    {
        'name': 'Cybersecurity & SOC',
        'category': 'Security',
        'description': 'End-to-end security operations centre (SOC) covering threat intelligence, SIEM, penetration testing, vulnerability management, and incident response retainer.',
        'poc_name': 'James Kowalski',
        'poc_email': 'j.kowalski@secureops.net',
        'poc_phone': '+1 (312) 555-0874',
    },
    {
        'name': 'AI & Machine Learning',
        'category': 'AI / ML',
        'description': 'Custom ML model development, NLP pipelines, computer vision solutions, and MLOps automation. Powered by TensorFlow, PyTorch, and GPT-based LLMs.',
        'poc_name': 'Aisha Rahman',
        'poc_email': 'aisha.r@ailab.tech',
        'poc_phone': '+92 300 5551234',
    },
    {
        'name': 'ERP & Business Software',
        'category': 'Enterprise',
        'description': 'Full ERP implementation (SAP, Odoo, Oracle) covering HR, Finance, Supply Chain, and CRM modules. Includes data migration, training, and ongoing support.',
        'poc_name': 'Carlos Mendez',
        'poc_email': 'c.mendez@erpsolutions.com',
        'poc_phone': '+44 20 7946 0988',
    },
    {
        'name': 'DevOps & CI/CD',
        'category': 'DevOps',
        'description': 'Pipeline automation with GitHub Actions, GitLab CI, and Jenkins. Docker / Kubernetes containerisation, Infrastructure as Code (Terraform), and release management.',
        'poc_name': 'Lena Fischer',
        'poc_email': 'lena.f@devbridge.de',
        'poc_phone': '+49 30 555 0222',
    },
    {
        'name': 'Data Analytics & BI',
        'category': 'Analytics',
        'description': 'End-to-end data warehousing, ETL pipelines (Apache Spark / dbt), and interactive BI dashboards using Power BI, Tableau, and Looker for real-time business insights.',
        'poc_name': 'Rohan Sharma',
        'poc_email': 'rohan.s@datawise.in',
        'poc_phone': '+91 98100 55678',
    },
]

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
# Support both env names for backward compatibility; prefer ALLOW_ADMIN_PASSWORD_UPDATE.
ALLOW_ADMIN_PASSWORD_UPDATE = (
    os.environ.get('ALLOW_ADMIN_PASSWORD_UPDATE') == '1'
    or os.environ.get('UPDATE_ADMIN_PASSWORD') == '1'
)
VALID_ROLES = {'User', 'Manager', 'Admin'}

def normalize_text(value):
    if value is None:
        return ''
    return value.strip()

def normalize_optional_text(value):
    cleaned = normalize_text(value)
    return cleaned or None

def normalize_role(value):
    cleaned = normalize_text(value)
    return cleaned if cleaned in VALID_ROLES else 'User'

def password_matches(stored_hash, candidate):
    if not stored_hash or not candidate:
        return False
    try:
        return check_password_hash(stored_hash, candidate)
    except ValueError:
        return False

def ensure_users_phone_column():
    try:
        inspector = inspect(db.engine)
        columns = {column['name'] for column in inspector.get_columns('users')}
    except SQLAlchemyError as exc:
        app.logger.warning(
            'Unable to inspect users table for phone column; continuing without schema fix: %s',
            exc
        )
        return
    if 'phone' in columns:
        return
    try:
        db.session.execute(text(PHONE_COLUMN_SQL))
        db.session.commit()
    except SQLAlchemyError as exc:
        app.logger.warning(
            'Unable to add users.phone column; user queries may fail until schema is updated: %s',
            exc
        )

with app.app_context():
    db.create_all()
    ensure_users_phone_column()
    # Seed services only if table is empty
    if Service.query.count() == 0:
        for s in DEFAULT_SERVICES:
            db.session.add(Service(**s))
        db.session.commit()
    admin_username = normalize_text(ADMIN_USERNAME)
    admin_password = normalize_text(ADMIN_PASSWORD)
    if admin_username and admin_password:
        admin = Admin.query.filter_by(username=admin_username).first()
        if not admin:
            db.session.add(Admin(
                username=admin_username,
                password=generate_password_hash(admin_password)
            ))
            db.session.commit()
        else:
            # Sync stored admin password only when explicitly enabled.
            if ALLOW_ADMIN_PASSWORD_UPDATE and not password_matches(admin.password, admin_password):
                admin.password = generate_password_hash(admin_password)
                db.session.commit()

# ─── HELPERS ───────────────────────────────────────────────────────────────────

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped

def verify_admin_password(admin, password):
    if not admin:
        return False
    return password_matches(admin.password, password)

# ─── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = normalize_text(request.form.get('username'))
        # Do not strip passwords to preserve intentional whitespace; default to '' for comparisons.
        password = request.form.get('password') or ''
        admin = Admin.query.filter_by(username=username).first()
        if verify_admin_password(admin, password):
            session['logged_in'] = True
            session['user'] = admin.username
            return redirect(url_for('dashboard'))
        flash('Access Denied: Invalid Credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── DASHBOARD ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    total_users    = User.query.filter_by(is_deleted=False).count()
    deleted_users  = User.query.filter_by(is_deleted=True).count()
    total_services = Service.query.filter_by(is_deleted=False).count()
    return render_template('index.html',
                           total_users=total_users,
                           deleted_users=deleted_users,
                           total_services=total_services)

# ─── USERS ROUTES ──────────────────────────────────────────────────────────────

@app.route('/users')
@login_required
def users():
    active_users = User.query.filter_by(is_deleted=False).order_by(User.created_at.desc()).all()
    return render_template('users.html', users=active_users)

@app.route('/add', methods=['POST'])
@login_required
def add_user():
    db.session.add(User(
        name  = normalize_text(request.form.get('name')),
        cnic  = normalize_text(request.form.get('cnic')),
        email = normalize_text(request.form.get('email')),
        phone = normalize_optional_text(request.form.get('phone')),
        role  = normalize_role(request.form.get('role', 'User')),
    ))
    db.session.commit()
    flash('User added successfully.')
    return redirect(url_for('users'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.name  = normalize_text(request.form.get('name'))
        user.cnic  = normalize_text(request.form.get('cnic'))
        user.email = normalize_text(request.form.get('email'))
        user.phone = normalize_optional_text(request.form.get('phone'))
        user.role  = normalize_role(request.form.get('role', 'User'))
        db.session.commit()
        flash('User updated successfully.')
        return redirect(url_for('users'))
    return render_template('edit.html', user=user)

@app.route('/delete/<int:id>')
@login_required
def delete_user(id):
    """Soft-delete: mark as deleted rather than removing from DB."""
    user = User.query.get_or_404(id)
    user.is_deleted = True
    user.deleted_at = datetime.utcnow()
    db.session.commit()
    flash(f'User "{user.name}" moved to trash.')
    return redirect(url_for('users'))

@app.route('/restore/<int:id>')
@login_required
def restore_user(id):
    user = User.query.get_or_404(id)
    user.is_deleted = False
    user.deleted_at = None
    db.session.commit()
    flash(f'User "{user.name}" restored successfully.')
    return redirect(url_for('trash'))

@app.route('/trash')
@login_required
def trash():
    deleted_users = User.query.filter_by(is_deleted=True).order_by(User.deleted_at.desc()).all()
    return render_template('trash.html', users=deleted_users)

# ─── SERVICES ROUTES ───────────────────────────────────────────────────────────

@app.route('/services')
@login_required
def services():
    all_services = Service.query.filter_by(is_deleted=False).order_by(Service.created_at.asc()).all()
    return render_template('services.html', services=all_services)

@app.route('/services/add', methods=['POST'])
@login_required
def add_service():
    db.session.add(Service(
        name        = normalize_text(request.form.get('name')),
        category    = normalize_text(request.form.get('category')),
        description = normalize_text(request.form.get('description')),
        poc_name    = normalize_text(request.form.get('poc_name')),
        poc_email   = normalize_text(request.form.get('poc_email')),
        poc_phone   = normalize_text(request.form.get('poc_phone')),
    ))
    db.session.commit()
    flash('Service added successfully.')
    return redirect(url_for('services'))

@app.route('/services/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_service(id):
    svc = Service.query.get_or_404(id)
    if request.method == 'POST':
        svc.name        = normalize_text(request.form.get('name'))
        svc.category    = normalize_text(request.form.get('category'))
        svc.description = normalize_text(request.form.get('description'))
        svc.poc_name    = normalize_text(request.form.get('poc_name'))
        svc.poc_email   = normalize_text(request.form.get('poc_email'))
        svc.poc_phone   = normalize_text(request.form.get('poc_phone'))
        db.session.commit()
        flash('Service updated.')
        return redirect(url_for('services'))
    return render_template('edit_service.html', svc=svc)

@app.route('/services/delete/<int:id>')
@login_required
def delete_service(id):
    svc = Service.query.get_or_404(id)
    svc.is_deleted = True
    db.session.commit()
    flash(f'Service "{svc.name}" removed.')
    return redirect(url_for('services'))

@app.route('/services/restore/<int:id>')
@login_required
def restore_service(id):
    svc = Service.query.get_or_404(id)
    svc.is_deleted = False
    db.session.commit()
    flash(f'Service "{svc.name}" restored.')
    return redirect(url_for('services'))

if __name__ == '__main__':
    if not is_debug and os.environ.get('ALLOW_DEV_SERVER') != '1':
        raise RuntimeError(
            "Cannot run Flask development server in production mode. Set FLASK_DEBUG=1 for development, "
            "set ALLOW_DEV_SERVER=1 to override, or use a production WSGI server like Gunicorn or uWSGI."
        )
    app.run(debug=is_debug)
