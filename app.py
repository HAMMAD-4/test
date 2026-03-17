from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'master_secure_key_123'

# WAMP Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/crud_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

with app.app_context():
    db.create_all()
    # Seed services only if table is empty
    if Service.query.count() == 0:
        for s in DEFAULT_SERVICES:
            db.session.add(Service(**s))
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

# ─── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        admin = Admin.query.filter_by(
            username=request.form['username'],
            password=request.form['password']
        ).first()
        if admin:
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
        name  = request.form.get('name'),
        cnic  = request.form.get('cnic'),
        email = request.form.get('email'),
        phone = request.form.get('phone'),
        role  = request.form.get('role', 'User'),
    ))
    db.session.commit()
    flash('User added successfully.')
    return redirect(url_for('users'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.name  = request.form.get('name')
        user.cnic  = request.form.get('cnic')
        user.email = request.form.get('email')
        user.phone = request.form.get('phone')
        user.role  = request.form.get('role', 'User')
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
        name        = request.form.get('name'),
        category    = request.form.get('category'),
        description = request.form.get('description'),
        poc_name    = request.form.get('poc_name'),
        poc_email   = request.form.get('poc_email'),
        poc_phone   = request.form.get('poc_phone'),
    ))
    db.session.commit()
    flash('Service added successfully.')
    return redirect(url_for('services'))

@app.route('/services/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_service(id):
    svc = Service.query.get_or_404(id)
    if request.method == 'POST':
        svc.name        = request.form.get('name')
        svc.category    = request.form.get('category')
        svc.description = request.form.get('description')
        svc.poc_name    = request.form.get('poc_name')
        svc.poc_email   = request.form.get('poc_email')
        svc.poc_phone   = request.form.get('poc_phone')
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
    app.run(debug=True)