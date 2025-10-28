from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_for_local_use')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///RonGwafo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------------------- #
# Database Models
# ----------------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    admin_token = db.Column(db.String(100))
    appointments = db.relationship('Appointment', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    contact_number = db.Column(db.String(50), nullable=False)
    preferred_date = db.Column(db.String(50), nullable=False)
    preferred_time = db.Column(db.String(50), nullable=False)
    remarks = db.Column(db.Text)
    payment_status = db.Column(db.String(50), default='Unpaid')
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ----------------------------- #
# Helper Decorators
# ----------------------------- #
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.", "error")
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'admin_id' not in session:
            flash("Admin access required.", "error")
            return redirect(url_for('admin_login'))
        return view(*args, **kwargs)
    return wrapped


# ----------------------------- #
# Routes
# ----------------------------- #
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin():
    return redirect(url_for('admin_login'))

# ----------------------------- #
# User Registration & Login
# ----------------------------- #
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        full_name = request.form.get('full_name')
        email = request.form.get('email')

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists.')

        user = User(username=username, full_name=full_name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        session['username'] = user.username
        flash('Registration successful. Welcome!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

# ----------------------------- #
# User Dashboard & Appointments
# ----------------------------- #
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    appointments = Appointment.query.filter_by(
        user_id=user.id).order_by(Appointment.created_at.desc()).all()
    return render_template('dashboard.html', user=user, appointments=appointments)

# ✅ New route to match base.html link
@app.route('/appointments')
@login_required
def appointments():
    """My Appointments page"""
    user = User.query.get(session['user_id'])
    appointments = Appointment.query.filter_by(
        user_id=user.id).order_by(Appointment.created_at.desc()).all()
    return render_template('appointments.html', user=user, appointments=appointments)

@app.route('/appointment/new', methods=['GET', 'POST'])
@login_required
def new_appointment():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        contact_number = request.form['contact_number']
        preferred_date = request.form['preferred_date']
        preferred_time = request.form['preferred_time']
        remarks = request.form.get('remarks')

        appt = Appointment(
            user_id=session['user_id'],
            full_name=full_name,
            email=email,
            contact_number=contact_number,
            preferred_date=preferred_date,
            preferred_time=preferred_time,
            remarks=remarks
        )
        db.session.add(appt)
        db.session.commit()
        flash('Appointment requested successfully!', 'success')
        return redirect(url_for('appointments'))

    return render_template('appointment.html')

@app.route('/appointment/<int:appt_id>/delete', methods=['POST'])
@login_required
def delete_appointment(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    user = User.query.get(session['user_id'])
    if appt.user_id != user.id:
        flash('You are not allowed to delete this appointment.', 'error')
        return redirect(url_for('dashboard'))
    db.session.delete(appt)
    db.session.commit()
    flash('Appointment deleted successfully.', 'info')
    return redirect(url_for('appointments'))

# ----------------------------- #
# Admin Token Login System
# ----------------------------- #
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        token = request.form.get('token', '').strip()

        admin = User.query.filter_by(is_admin=True).first()
        valid_token = admin.admin_token if admin else os.environ.get('ADMIN_TOKEN', 'tdc_admin_token123')

        if admin and token == valid_token:
            session['admin_id'] = admin.id
            session['admin_name'] = admin.full_name
            flash('Admin access granted.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin token.', 'error')

    return render_template('admin_login.html')

# ----------------------------- #
# Admin Dashboard & Management
# ----------------------------- #
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    appointments = Appointment.query.order_by(Appointment.created_at.desc()).all()
    return render_template('admin.html', appointments=appointments)

@app.route('/admin/appointment/<int:appt_id>/status', methods=['POST'])
@admin_required
def change_status(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    appt.status = request.form.get('status')
    appt.payment_status = request.form.get('payment_status', appt.payment_status)
    db.session.commit()
    flash('Appointment updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('index'))

# ----------------------------- #
# App Init
# ----------------------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # ✅ Create default admin account if missing
        default_admin = User.query.filter_by(username='admin').first()
        if not default_admin:
            admin = User(
                username='admin',
                full_name='Administrator',
                email='admin@example.com',
                is_admin=True,
                admin_token='tdc_admin_token123'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✅ Default admin created:")
            print("   Username: admin")
            print("   Password: admin123")
            print("   Token: tdc_admin_token123")
        else:
            print("ℹ️ Admin already exists.")

    app.run(debug=True)
