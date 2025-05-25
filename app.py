from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import pyotp
import base64
from functools import wraps
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler
import os
from OpenSSL import SSL
from dotenv import load_dotenv
import csv
from io import StringIO
from flask import Response
from sqlalchemy import text
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import qrcode
from io import BytesIO
import atexit

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # global limits
    storage_uri="memory://",
)

# MySQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/secure_health'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)

# Encryption
with open('fernet.key', 'rb') as f:
    key = f.read()
cipher_suite = Fernet(key)

# Logging
handler = RotatingFileHandler('secure_health.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, doctor, patient
    two_factor_secret = db.Column(db.String(16))
    is_active = db.Column(db.Boolean, default=True)
    phone = db.Column(db.String(20))  # Add this line

class PatientRecord(db.Model):
    __tablename__ = 'patient_records'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    diagnosis = db.Column(db.Text, nullable=False)  # Encrypted
    prescription = db.Column(db.Text)  # Encrypted
    notes = db.Column(db.Text)  # Encrypted
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    appointment_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled')
    reason = db.Column(db.Text)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Helper Functions
def encrypt_data(data):
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

def log_activity(user_id, action, details=""):
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=request.remote_addr,
        details=details
    )
    db.session.add(audit_log)
    db.session.commit()

def generate_jwt_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.secret_key, algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return redirect(url_for('login'))
        if not current_user.is_active:
            session.clear()
            flash('Your account is deactivated. Please contact admin.', 'danger')
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user.role not in roles:
                flash('Unauthorized access', 'danger')
                return redirect(url_for('dashboard'))
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password) and
        re.search(r'[^A-Za-z0-9]', password)
    )

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        if not user.is_active:
            flash('Your account is deactivated. Please contact admin.', 'danger')
            return redirect(url_for('login'))
        if check_password_hash(user.password, password):
            if user.role in ['admin', 'doctor'] and user.two_factor_secret:
                session['pre_2fa_user'] = user.id
                return redirect(url_for('verify_2fa'))
            
            session['user_id'] = user.id
            session['role'] = user.role
            session['token'] = generate_jwt_token(user.id, user.role)
            log_activity(user.id, 'LOGIN_SUCCESS')
            return redirect(url_for('dashboard'))
        
        log_activity(None, 'LOGIN_FAILED', details=f"Failed login for {username}")
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        phone = request.form['phone']  # <-- Add this line

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        if not is_strong_password(password):
            flash('Password must be at least 8 characters, include an uppercase letter, a lowercase letter, a number, and a special character.', 'danger')
            return redirect(url_for('register'))

        # Always generate a 2FA secret
        two_factor_secret = pyotp.random_base32()
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role,
            phone=phone  # <-- Save phone number
        )
        db.session.add(new_user)
        db.session.commit()
        session['pre_2fa_user'] = new_user.id
        return redirect(url_for('setup_2fa'))

    return render_template('register.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['pre_2fa_user'])
    
    if request.method == 'POST':
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(request.form['token']):
            session['user_id'] = user.id
            session['role'] = user.role
            session['token'] = generate_jwt_token(user.id, user.role)
            session.pop('pre_2fa_user', None)
            log_activity(user.id, '2FA_SUCCESS')
            return redirect(url_for('dashboard'))
        
        log_activity(user.id, '2FA_FAILED')
        flash('Invalid 2FA token', 'danger')
        return redirect(url_for('verify_2fa'))
    
    return render_template('2fa_verify.html')

@app.route('/setup-2fa', methods=['GET'])
def setup_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['pre_2fa_user'])
    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()
        db.session.commit()
    uri = pyotp.totp.TOTP(user.two_factor_secret).provisioning_uri(
        name=user.username,
        issuer_name='Secure Health'
    )
    # Generate QR code as base64
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template(
        '2fa_setup.html',
        qr_b64=qr_b64,
        totp_secret=user.two_factor_secret
    )

@app.route('/dashboard')
@token_required
def dashboard(current_user):
    if current_user.role == 'admin':
        users = User.query.all()
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
        return render_template('dashboard_admin.html', users=users, logs=logs)
    elif current_user.role == 'doctor':
        patients = User.query.filter_by(role='patient').all()
        records = PatientRecord.query.filter_by(doctor_id=current_user.id).all()
        appointments = Appointment.query.filter_by(doctor_id=current_user.id).all()
        return render_template(
            'dashboard_doctor.html',
            patients=patients,
            appointments=appointments,
            records=records,
            User=User  # <-- Add this line
        )
    else:
        # For patient dashboard
        records = PatientRecord.query.filter_by(patient_id=current_user.id).all()
        appointments = Appointment.query.filter_by(patient_id=current_user.id).all()
        doctors = User.query.filter_by(role='doctor').all()
        return render_template(
            'dashboard_patient.html',
            records=records,
            appointments=appointments,
            doctors=doctors,
            User=User  # <-- Add this line
        )
    

@app.context_processor
def utility_processor():
    def get_doctors():
        return User.query.filter_by(role='doctor').all()
    return dict(get_doctors=get_doctors)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'LOGOUT')
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# Admin routes
@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@token_required
@role_required(['admin'])
def toggle_user(current_user, user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    log_activity(current_user.id, 'TOGGLE_USER', details=f"Toggled user {user.username} to {'active' if user.is_active else 'inactive'}")
    return jsonify({'success': True, 'is_active': user.is_active})

@app.route('/admin/logs/export')
@token_required
@role_required(['admin'])
def export_logs(current_user):
    logs = AuditLog.query.all()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['id', 'user_id', 'action', 'ip_address', 'details', 'created_at'])
    for log in logs:
        cw.writerow([log.id, log.user_id, log.action, log.ip_address, log.details, log.created_at])
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=audit_logs.csv"})

@app.route('/admin/grant', methods=['POST'])
@token_required
@role_required(['admin'])
def grant_permission(current_user):
    db_user = request.form['db_user']
    permission = request.form['permission']
    table = request.form['table']
    sql = f"GRANT {permission} ON secure_health.{table} TO '{db_user}'@'localhost';"
    db.session.execute(text(sql))
    db.session.commit()
    log_activity(current_user.id, 'GRANT_PERMISSION', details=sql)
    flash('Permission granted', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/revoke', methods=['POST'])
@token_required
@role_required(['admin'])
def revoke_permission(current_user):
    db_user = request.form['db_user']
    permission = request.form['permission']
    table = request.form['table']
    sql = f"REVOKE {permission} ON secure_health.{table} FROM '{db_user}'@'localhost';"
    db.session.execute(text(sql))
    db.session.commit()
    log_activity(current_user.id, 'REVOKE_PERMISSION', details=sql)
    flash('Permission revoked', 'success')
    return redirect(url_for('dashboard'))

# Doctor routes
@app.route('/doctor/records/add', methods=['POST'])
@token_required
@role_required(['doctor'])
def add_record(current_user):
    patient_id = request.form['patient_id']
    diagnosis = encrypt_data(request.form['diagnosis'])
    prescription = encrypt_data(request.form['prescription']) if request.form['prescription'] else None
    notes = encrypt_data(request.form['notes']) if request.form['notes'] else None
    
    new_record = PatientRecord(
        patient_id=patient_id,
        doctor_id=current_user.id,
        diagnosis=diagnosis,
        prescription=prescription,
        notes=notes
    )
    db.session.add(new_record)
    db.session.commit()
    
    log_activity(current_user.id, 'ADD_RECORD', details=f"For patient ID: {patient_id}")
    flash('Record added successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/doctor/records/edit/<int:record_id>', methods=['GET', 'POST'])
@token_required
@role_required(['doctor'])
def edit_record(current_user, record_id):
    record = PatientRecord.query.get_or_404(record_id)
    if record.doctor_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        record.diagnosis = encrypt_data(request.form['diagnosis'])
        record.prescription = encrypt_data(request.form['prescription']) if request.form['prescription'] else None
        record.notes = encrypt_data(request.form['notes']) if request.form['notes'] else None
        db.session.commit()
        log_activity(current_user.id, 'EDIT_RECORD', details=f"Record ID: {record_id}")
        flash('Record updated', 'success')
        return redirect(url_for('dashboard'))
    # Decrypt for display
    record.diagnosis = decrypt_data(record.diagnosis)
    record.prescription = decrypt_data(record.prescription) if record.prescription else ''
    record.notes = decrypt_data(record.notes) if record.notes else ''
    return render_template('edit_record.html', record=record)

@app.route('/doctor/records/delete/<int:record_id>', methods=['POST'])
@token_required
@role_required(['doctor'])
def delete_record(current_user, record_id):
    record = PatientRecord.query.get_or_404(record_id)
    if record.doctor_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(record)
    db.session.commit()
    log_activity(current_user.id, 'DELETE_RECORD', details=f"Record ID: {record_id}")
    flash('Record deleted', 'success')
    return redirect(url_for('dashboard'))

# Patient routes
@app.route('/patient/appointments/book', methods=['POST'])
@token_required
@role_required(['patient'])
def book_appointment(current_user):
    doctor_id = request.form['doctor_id']
    appointment_time = datetime.datetime.strptime(
        request.form['appointment_time'], 
        '%Y-%m-%dT%H:%M'
    )
    reason = request.form['reason']
    
    new_appointment = Appointment(
        patient_id=current_user.id,
        doctor_id=doctor_id,
        appointment_time=appointment_time,
        reason=reason
    )
    db.session.add(new_appointment)
    db.session.commit()
    
    log_activity(current_user.id, 'BOOK_APPOINTMENT', details=f"With doctor ID: {doctor_id}")
    flash('Appointment booked successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/patient/profile', methods=['GET', 'POST'])
@token_required
@role_required(['patient'])
def edit_profile(current_user):
    if request.method == 'POST':
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        db.session.commit()
        flash('Profile updated', 'success')
        return redirect(url_for('edit_profile'))
    return render_template('edit_profile_patient.html', user=current_user)

@app.route('/patient/change-password', methods=['POST'])
@token_required
@role_required(['patient'])
def change_password(current_user):
    old = request.form['old_password']
    new = request.form['new_password']
    if not check_password_hash(current_user.password, old):
        flash('Old password incorrect', 'danger')
        return redirect(url_for('edit_profile'))
    current_user.password = generate_password_hash(new)
    db.session.commit()
    flash('Password changed', 'success')
    return redirect(url_for('edit_profile'))

@app.route('/patient/appointments/cancel/<int:appointment_id>', methods=['POST'])
@token_required
@role_required(['patient'])
def cancel_appointment(current_user, appointment_id):
    appt = Appointment.query.get_or_404(appointment_id)
    if appt.patient_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    appt.status = 'cancelled'
    db.session.commit()
    log_activity(current_user.id, 'CANCEL_APPOINTMENT', details=f"Appointment ID: {appointment_id}")
    flash('Appointment cancelled', 'success')
    return redirect(url_for('dashboard'))

@app.route('/doctor/profile', methods=['GET', 'POST'])
@token_required
@role_required(['doctor'])
def doctor_profile(current_user):
    if request.method == 'POST':
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        db.session.commit()
        flash('Profile updated', 'success')
        return redirect(url_for('doctor_profile'))
    return render_template('edit_profile_doctor.html', user=current_user)

@app.route('/doctor/change-password', methods=['POST'])
@token_required
@role_required(['doctor'])
def doctor_change_password(current_user):
    old = request.form['old_password']
    new = request.form['new_password']
    if not check_password_hash(current_user.password, old):
        flash('Old password incorrect', 'danger')
        return redirect(url_for('doctor_profile'))
    current_user.password = generate_password_hash(new)
    db.session.commit()
    flash('Password changed', 'success')
    return redirect(url_for('doctor_profile'))

@app.route('/vuln_search', methods=['GET', 'POST'])
def vuln_search():
    results = []
    if request.method == 'POST':
        query = request.form['query']
        # VULNERABLE: Directly interpolating user input into SQL
        sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        results = db.session.execute(text(sql)).fetchall()  # <-- wrap with text()
    return render_template('vuln_search.html', results=results)

comments = []

@app.route('/vuln_comment', methods=['GET', 'POST'])
def vuln_comment():
    global comments
    if request.method == 'POST':
        comment = request.form['comment']
        comments.append(comment)  # No sanitization!
    return render_template('vuln_comment.html', comments=comments)

def export_logs_on_exit():
    with app.app_context():
        logs = AuditLog.query.order_by(AuditLog.created_at).all()
        with open("secure_health_log.txt", "w", encoding="utf-8") as f:
            for log in logs:
                f.write(f"{log.created_at} | User: {log.user_id} | Action: {log.action} | IP: {log.ip_address} | Details: {log.details}\n")

atexit.register(export_logs_on_exit)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email='admin@securehealth.com',
                password=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
    
    # For development only - in production use proper SSL certificates
    context = ('cert.pem', 'key.pem')  
    app.run( ssl_context=context,host='0.0.0.0', port=8000)