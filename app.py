from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_for_local_use')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///RonGwafo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
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
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return view(*args, **kwargs)
    return wrapped

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
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

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username'].strip().lower()
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        flash('Logged in successfully.', 'success')
        return redirect(url_for('dashboard'))
    flash('Invalid username or password.', 'error')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    appointments = Appointment.query.filter_by(user_id=user.id).order_by(Appointment.created_at.desc()).all()
    return render_template('dashboard.html', user=user, appointments=appointments)

@app.route('/appointment/new', methods=['GET','POST'])
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
            user_id = session['user_id'],
            full_name = full_name,
            email = email,
            contact_number = contact_number,
            preferred_date = preferred_date,
            preferred_time = preferred_time,
            remarks = remarks
        )
        db.session.add(appt)
        db.session.commit()
        flash('Appointment requested. You will see it in your dashboard.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('appointment.html')

@app.route('/appointments')
@login_required
def my_appointments():
    user = User.query.get(session['user_id'])
    appointments = Appointment.query.filter_by(user_id=user.id).order_by(Appointment.created_at.desc()).all()
    return render_template('appointments.html', appointments=appointments, admin_view=False)

@app.route('/admin/appointments')
@admin_required
def admin_appointments():
    all_appts = Appointment.query.order_by(Appointment.created_at.desc()).all()
    return render_template('appointments.html', appointments=all_appts, admin_view=True)

@app.route('/appointment/<int:appt_id>/delete', methods=['POST'])
@login_required
def delete_appointment(appt_id):
    appt = Appointment.query.get_or_404(appt_id)
    user = User.query.get(session['user_id'])
    if appt.user_id != user.id and not user.is_admin:
        flash('Not allowed to delete.', 'error')
        return redirect(url_for('dashboard'))
    db.session.delete(appt)
    db.session.commit()
    flash('Appointment deleted.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/admin/appointment/<int:appt_id>/status', methods=['POST'])
@admin_required
def change_status(appt_id):
    status = request.form.get('status')
    appt = Appointment.query.get_or_404(appt_id)
    appt.status = status
    db.session.commit()
    flash('Status updated.', 'success')
    return redirect(url_for('admin_appointments'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # create default admin if not present
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', full_name='Administrator', email='admin@example.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
