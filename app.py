import os
import datetime
from datetime import timedelta, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Cleaned up app configuration and used the variables from the user's provided code
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_for_local_use')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///RonGwafo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setting a default session lifetime is optional but good practice (using timedelta import)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

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

    # Use timezone-aware datetime.now(timezone.utc)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))


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
@app.context_processor
def inject_now():
    """Injects the current datetime object (callable) into all templates."""
    # Ensure it's passed as a callable function so templates can use now().year
    return {'now': datetime.datetime.now}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about_us():
    """Renders the About Us page with the booking guide."""
    return render_template('about.html')


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
    # user object is needed in the template for pre-filling name/email
    user = User.query.get(session['user_id'])

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

    # Pass user object to template for new appointment form
    return render_template('appointment.html', user=user)


@app.route('/appointment/<int:appt_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_appointment(appt_id):
    """Allows a user to edit their pending appointment."""
    appt = Appointment.query.get_or_404(appt_id)
    user = User.query.get(session['user_id'])

    # Security check: Ensure the user owns the appointment
    if appt.user_id != user.id:
        flash('You are not allowed to edit this appointment.', 'error')
        return redirect(url_for('appointments'))

    # Logic check: Prevent editing of Confirmed/Completed/Paid appointments
    # Only 'Pending' and possibly 'Cancelled' appointments can be edited.
    if appt.status not in ['Pending', 'Cancelled']:
        flash(f'Cannot edit appointment with status: {appt.status}.', 'error')
        return redirect(url_for('appointments'))

    if request.method == 'POST':
        # Update fields
        appt.full_name = request.form['full_name']
        appt.email = request.form['email']
        appt.contact_number = request.form['contact_number']
        appt.preferred_date = request.form['preferred_date']
        appt.preferred_time = request.form['preferred_time']
        appt.remarks = request.form.get('remarks')

        # If they successfully updated, set status back to Pending for admin review
        if appt.status != 'Pending':
            appt.status = 'Pending'

        db.session.commit()
        flash('Appointment updated successfully! Please note the admin must review the change.', 'success')
        return redirect(url_for('appointments'))

    # GET request: Render the appointment form with existing data
    # Pass both the appointment object and the user object
    return render_template('appointment.html', appt=appt, user=user)


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
    MAX_ATTEMPTS = 3
    LOCKOUT_DURATION = timedelta(hours=1)

    # Get current UTC time
    current_utc_time = datetime.datetime.now(timezone.utc)

    # --- Check for existing lockout ---
    if 'admin_lockout_until' in session:
        lockout_time_str = session['admin_lockout_until']

        # Ensure we parse the string correctly and set timezone info for comparison
        try:
            lockout_time_aware = datetime.datetime.fromisoformat(lockout_time_str).replace(tzinfo=timezone.utc)
        except ValueError:
            session.pop('admin_lockout_until', None)
            session.pop('admin_login_attempts', None)
            lockout_time_aware = datetime.datetime.min.replace(tzinfo=timezone.utc)

        # Compare aware datetimes
        if current_utc_time < lockout_time_aware:
            remaining = lockout_time_aware - current_utc_time
            flash(
                f"Login locked. Try again in {int(remaining.total_seconds() // 60)} minutes and {int(remaining.total_seconds() % 60)} seconds.",
                'error')
            if request.method == 'POST':
                return redirect(url_for('admin_login'))
            return render_template('admin_login.html')
        else:
            # Lockout expired, clear session variables
            session.pop('admin_lockout_until', None)
            session.pop('admin_login_attempts', None)

    if request.method == 'POST':
        token = request.form.get('token', '').strip()

        admin = User.query.filter_by(is_admin=True).first()
        valid_token = admin.admin_token if admin else os.environ.get('ADMIN_TOKEN', 'RonGwafu-Admin')

        # Initialize/increment attempt counter
        session['admin_login_attempts'] = session.get('admin_login_attempts', 0) + 1
        attempts_left = MAX_ATTEMPTS - session['admin_login_attempts']

        if admin and token == valid_token:
            # --- Successful Login: Clear attempts and grant access ---
            session.pop('admin_login_attempts', None)
            session.pop('admin_lockout_until', None)

            session['admin_id'] = admin.id
            session['admin_name'] = admin.full_name
            flash('Admin access granted.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            # --- Failed Login Attempt ---
            if session['admin_login_attempts'] >= MAX_ATTEMPTS:
                # --- Lockout Triggered ---
                lockout_time = current_utc_time + LOCKOUT_DURATION
                session['admin_lockout_until'] = lockout_time.isoformat()
                session.pop('admin_login_attempts', None)
                flash(f'Invalid token. Maximum login attempts reached. Access locked for 1 hour.', 'error')
                return redirect(url_for('admin_login'))
            else:
                # --- Failed Attempt, not yet locked out ---
                flash(f'Invalid admin token. {attempts_left} attempts remaining.', 'error')

    return render_template('admin_login.html')


# ----------------------------- #
# Admin Dashboard & Management
# ----------------------------- #
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Sort by status (Pending first) and then by oldest creation date
    appointments = Appointment.query.order_by(
        Appointment.status,
        Appointment.created_at.asc()
    ).all()
    # Pass admin_view=True to the template for conditional display
    return render_template('admin.html', appointments=appointments, admin_view=True)


# New Route for detailed view of a single appointment
@app.route('/admin/appointment/<int:appt_id>')
@admin_required
def admin_appointment_detail(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    # Find the user associated with the appointment for extra info if needed
    user = User.query.get(appt.user_id)
    return render_template('admin_detail.html', appt=appt, user=user)


@app.route('/admin/appointment/<int:appt_id>/status', methods=['POST'])
@admin_required
def change_status(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    appt.status = request.form.get('status')
    appt.payment_status = request.form.get('payment_status', appt.payment_status)
    appt.remarks = request.form.get('remarks', appt.remarks)
    db.session.commit()
    flash('Appointment updated successfully.', 'success')
    # Redirect back to the detail page instead of the main dashboard
    return redirect(url_for('admin_appointment_detail', appt_id=appt_id))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/Dev-Request-Reset')
def admin_unlock_session():
    was_locked = 'admin_lockout_until' in session or 'admin_login_attempts' in session
    session.pop('admin_lockout_until', None)
    session.pop('admin_login_attempts', None)
    if was_locked:
        flash("Request Granted. You can now try logging in again.", 'success')
    else:
        flash("No active admin lockout found in this session.", 'info')

    return redirect(url_for('admin_login'))

# Note: The 'app.run(debug=True)' line was removed as execution is handled by the environment.