# Secure Hospital Management System

## Overview
This is a secure hospital management system designed with robust security features including two-factor authentication (2FA), encrypted data storage, and secure communication protocols. The system serves different user roles including administrators, doctors, and patients.

## Features
- Multi-user role support (Admin, Doctor, Patient)
- Two-factor authentication (2FA)
- Secure data encryption
- HTTPS/SSL implementation
- Secure session management
- Profile management for doctors and patients
- Medical record management
- Vulnerability testing features

## Technical Stack
- Python Flask web framework
- SQLite database
- Fernet encryption
- SSL/TLS for secure communication
- Custom password generation utility

## Project Structure
```
hospital2/
├── static/          # Static assets (CSS, JS)
├── templates/       # HTML templates
├── app.py          # Main application file
├── fernet_create.py # Encryption key generation
├── password_gen.py # Password utility
└── requirements.txt # Project dependencies
```

## Security Features
- Encrypted data storage using Fernet
- SSL/TLS implementation with custom certificates
- Two-factor authentication
- Secure password policies
- Session management
- Input validation and sanitization

## Setup and Installation
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Generate encryption keys:
   ```bash
   python fernet_create.py
   ```
3. Configure SSL certificates (cert.pem and key.pem)
4. Start the application:
   ```bash
   python app.py
   ```

## User Roles
### Administrator
- System management
- User management
- Access control

### Doctor
- View and manage patient records
- Update profile information
- Manage appointments

### Patient
- View medical records
- Update personal information
- Schedule appointments

## Security Guidelines
- Regularly update passwords
- Enable 2FA for additional security
- Keep encryption keys secure
- Monitor system logs
- Regular security audits

## Logging
The system maintains detailed logs for security monitoring and auditing purposes:
- secure_health.log
- secure_health_log.txt





