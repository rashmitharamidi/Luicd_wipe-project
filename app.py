from flask import Flask, request, render_template, send_file, session, redirect, url_for, flash
import os
import re
import pytesseract
from pdf2image import convert_from_path
from PIL import Image, ImageDraw
import numpy as np
import cv2
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import uuid
import io
import secrets
import functools
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
os.makedirs('uploads', exist_ok=True)

# Database configuration
DB_CONFIG = {
    'dbname': 'piidb',
    'user': 'postgres',
    'password': '5432',
    'host': 'localhost'
}
# Define static patterns - keeping this as is
PII_PATTERNS = {
    'Aadhaar': r'(?<!\d)\d{4}\s\d{4}\s\d{4}(?!\d)',  # Only match exactly 12 digits with spaces
    'PAN': r'\b[A-Z]{5}\d{4}[A-Z]\b',
    'Phone Number': r'\b\d{10}\b'
}
# Create database tables if they don't exist
def init_db():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Create tables for users, documents, and encryption keys
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cur.execute('''
    CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        uuid VARCHAR(36) UNIQUE NOT NULL,
        original_filename VARCHAR(255) NOT NULL,
        encrypted_data BYTEA NOT NULL,
        uploaded_by INTEGER REFERENCES users(id),
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        pii_types VARCHAR(255) NOT NULL
    )
    ''')
    
    cur.execute('''
    CREATE TABLE IF NOT EXISTS encryption_keys (
        id SERIAL PRIMARY KEY,
        document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
        key_data BYTEA NOT NULL
    )
    ''')
    
    # Create admin account if it doesn't exist
    cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admin_count = cur.fetchone()[0]
    
    if admin_count == 0:
        # Create admin account
        admin_password = generate_password_hash("admin123")
        cur.execute(
            "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
            ("admin", admin_password, "admin", "approved")
        )
        
        # Create manager account
        manager_password = generate_password_hash("manager123")
        cur.execute(
            "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
            ("manager", manager_password, "manager", "approved")
        )
        
        # Create customer account
        customer_password = generate_password_hash("customer123")
        cur.execute(
            "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
            ("customer", customer_password, "customer", "approved")
        )
        
        # Create hacker account (limited role)
        hacker_password = generate_password_hash("hacker123")
        cur.execute(
            "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
            ("hacker", hacker_password, "hacker", "approved")
        )
    
    conn.commit()
    conn.close()

# Authentication decorator
def login_required(role=None):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            if role:
                conn = psycopg2.connect(**DB_CONFIG)
                cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                cur.execute("SELECT role, status FROM users WHERE id = %s", (session['user_id'],))
                user = cur.fetchone()
                conn.close()
                
                if user['status'] != 'approved':
                    flash('Your account is pending approval. Please wait for admin approval.')
                    return redirect(url_for('login'))
                
                if role != 'any' and user['role'] != role and (isinstance(role, list) and user['role'] not in role):
                    flash('You do not have permission to access this resource.')
                    return redirect(url_for('dashboard'))
                    
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# KEEP EXISTING FUNCTIONS AS IS
def redact_image(image, pii_to_redact):
    draw = ImageDraw.Draw(image)
    cv_img = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    data = pytesseract.image_to_data(thresh, config='--psm 6', output_type=pytesseract.Output.DICT)

    words = []
    for i in range(len(data['text'])):
        word = data['text'][i].strip()
        if word:
            words.append({
                'text': word,
                'left': data['left'][i],
                'top': data['top'][i],
                'width': data['width'][i],
                'height': data['height'][i]
            })

    word_texts = [w['text'] for w in words]
    full_text = " ".join(word_texts)
    # 1. Regex-based masking
    for pii_type in pii_to_redact:
        pattern = PII_PATTERNS.get(pii_type)
        if not pattern:
            continue
        for match in re.finditer(pattern, full_text):
            match_text = match.group()
            match_words = match_text.split()

            matched_boxes = []
            i = 0
            while i < len(word_texts):
                if word_texts[i] == match_words[0]:
                    group = [words[i]]
                    for j in range(1, len(match_words)):
                        if i + j < len(word_texts) and word_texts[i + j] == match_words[j]:
                            group.append(words[i + j])
                        else:
                            break
                    if len(group) == len(match_words):
                        matched_boxes.append(group)
                        i += len(group) - 1
                i += 1

            for group in matched_boxes:
                x0 = min(w['left'] for w in group)
                y0 = min(w['top'] for w in group)
                x1 = max(w['left'] + w['width'] for w in group)
                y1 = max(w['top'] + w['height'] for w in group)
                draw.rectangle([x0, y0, x1, y1], fill="black")
    return image

def _redact_matching_line(draw, image, line_text):
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    line_text_lower = line_text.strip().lower()
    line_boxes = []

    for i in range(len(data['text'])):
        word = data['text'][i].strip()
        if word and word.lower() in line_text_lower:
            box = (
                data['left'][i],
                data['top'][i],
                data['left'][i] + data['width'][i],
                data['top'][i] + data['height'][i]
            )
            line_boxes.append(box)

    if line_boxes:
        x0 = min(b[0] for b in line_boxes)
        y0 = min(b[1] for b in line_boxes)
        x1 = max(b[2] for b in line_boxes)
        y1 = max(b[3] for b in line_boxes)
        draw.rectangle([x0, y0, x1, y1], fill="black")

# ENCRYPTION FUNCTIONS
def generate_encryption_key():
    """Generate a secure encryption key"""
    return Fernet.generate_key()

def encrypt_file(file_data, key):
    """Encrypt file data using the given key"""
    f = Fernet(key)
    return f.encrypt(file_data)

def decrypt_file(encrypted_data, key):
    f = Fernet(key)
    # Ensure encrypted_data is bytes
    if isinstance(encrypted_data, memoryview):
        encrypted_data = encrypted_data.tobytes()
    elif isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    return f.decrypt(encrypted_data)

# ROUTES
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            if user['status'] == 'pending':
                flash('Your account is pending approval. Please wait for admin approval.')
                return render_template('login.html')
                
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Prevent manager registration through normal registration form
        if role == 'manager':
            flash('Manager accounts can only be created by administrators.')
            return render_template('register.html')
        
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Check if username already exists
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            conn.close()
            flash('Username already exists')
            return render_template('register.html')
        
        # Create new user with pending status
        hashed_password = generate_password_hash(password)
        if role=='hacker':
            cur.execute(
                "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
                (username, hashed_password, role, 'approved')
            )
        else:
            cur.execute(
                "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
                (username, hashed_password, role, 'pending')
            )
        conn.commit()
        conn.close()
        if role=='customer':
            flash('Registration successful! Please wait for admin approval before logging in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required(role='any')
def dashboard():
    role = session.get('role')
    
    # Redirect to appropriate dashboard based on role
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    # Get list of documents for all users to view
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("""
        SELECT d.id, d.uuid, d.original_filename, d.upload_date, d.pii_types, u.username as uploaded_by 
        FROM documents d 
        JOIN users u ON d.uploaded_by = u.id
        ORDER BY d.upload_date DESC
    """)
    documents = cur.fetchall()
    conn.close()
    
    if role == 'customer':
        return render_template('customer_dashboard.html', documents=documents)
    elif role == 'manager':
        return render_template('manager_dashboard.html', documents=documents)
    elif role == 'hacker':
        return render_template('hacker_dashboard.html', documents=documents)
    
    return "Unknown role"

# ADMIN ROUTES
@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    # Get user statistics
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Count users by role and status
    cur.execute("""
        SELECT role, status, COUNT(*) as count 
FROM users 
WHERE role != 'admin'
GROUP BY role, status 
ORDER BY role, status
    """)
    user_stats = cur.fetchall()
    
    # Calculate total users
    cur.execute("SELECT COUNT(*) as total FROM users WHERE role !='admin'")
    total_users = cur.fetchone()['total']
    
    # Get pending approval requests
    cur.execute("""
        SELECT COUNT(*) as pending
        FROM users
        WHERE status = 'pending' AND role != 'admin'
    """)
    pending_count = cur.fetchone()['pending']
    
    # Get document statistics
    cur.execute("SELECT COUNT(*) as doc_count FROM documents")
    doc_count = cur.fetchone()['doc_count']
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                           user_stats=user_stats, 
                           pending_count=pending_count,
                           doc_count=doc_count,
                           total_users=total_users)

@app.route('/admin/managers')
@login_required(role='admin')
def admin_managers():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Get all managers
    cur.execute("""
        SELECT id, username, created_at, status
        FROM users
        WHERE role = 'manager'
        ORDER BY created_at DESC
    """)
    managers = cur.fetchall()
    conn.close()
    
    return render_template('admin_managers.html', managers=managers)

@app.route('/admin/managers/create', methods=['GET', 'POST'])
@login_required(role='admin')
def create_manager():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Check if username already exists
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            conn.close()
            flash('Username already exists')
            return redirect(url_for('create_manager'))
        
        # Create new manager
        hashed_password = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
            (username, hashed_password, 'manager', 'approved')
        )
        conn.commit()
        conn.close()
        
        flash(f'Manager account for {username} created successfully!')
        return redirect(url_for('admin_managers'))
    
    return render_template('create_manager.html')

@app.route('/admin/managers/delete/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def delete_manager(user_id):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Verify the user is a manager
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    
    if not user or user[0] != 'manager':
        conn.close()
        flash('User not found or not a manager')
        return redirect(url_for('admin_managers'))
    
    # Delete the manager account
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    
    flash('Manager account deleted successfully')
    return redirect(url_for('admin_managers'))

@app.route('/admin/users')
@login_required(role='admin')
def admin_users():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Get all users except admins and managers
    cur.execute("""
        SELECT id, username, role, status, created_at
        FROM users
        WHERE role IN ('customer', 'hacker')
        ORDER BY status DESC, created_at DESC
    """)
    users = cur.fetchall()
    
    # Get pending users separately
    cur.execute("""
        SELECT id, username, role, status, created_at
        FROM users
        WHERE status = 'pending' AND role IN ('customer', 'hacker')
        ORDER BY created_at DESC
    """)
    pending_users = cur.fetchall()
    
    conn.close()
    
    return render_template('admin_users.html', users=users, pending_users=pending_users)

@app.route('/admin/users/approve/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def approve_user(user_id):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Approve the user
    cur.execute("UPDATE users SET status = 'approved' WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    
    flash('User approved successfully')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/reject/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def reject_user(user_id):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Reject by deleting the user
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    
    flash('User rejected and deleted successfully')
    return redirect(url_for('admin_users'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required(role='customer')
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')
        
    file = request.files.get('file')
    if not file or file.filename == '':
        return "No file uploaded", 400

    input_path = os.path.join('uploads', file.filename)
    file.save(input_path)

    images = convert_from_path(input_path, first_page=1, last_page=1)
    text = pytesseract.image_to_string(images[0])
    
    # Create a unique ID for this extraction
    extraction_id = str(uuid.uuid4())
    
    # 1. Save extracted text to a file
    text_filename = f"extracted_text_{file.filename}.txt"
    text_filepath = os.path.join('uploads', text_filename)
    with open(text_filepath, 'w', encoding='utf-8') as text_file:
        text_file.write(text)
    
    # 2. Detect PII and save to a separate file
    detected_pii = {}
    for key, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            detected_pii[key] = matches
    
    # Save detected PII to a file
    pii_filename = f"detected_pii_{file.filename}.txt"
    pii_filepath = os.path.join('uploads', pii_filename)
    with open(pii_filepath, 'w', encoding='utf-8') as pii_file:
        pii_file.write("PII Detection Results\n")
        pii_file.write("-------------------\n\n")
        for pii_type, values in detected_pii.items():
            pii_file.write(f"Type: {pii_type}\n")
            for idx, value in enumerate(values, 1):
                pii_file.write(f"  Value {idx}: {value}\n")
            pii_file.write("\n")
    
    # Store the filenames in the session for future reference
    session['text_file'] = text_filename
    session['pii_file'] = pii_filename
    
    return render_template('select_pii.html', 
                          pii_types=list(detected_pii.keys()), 
                          input_file=file.filename,
                          text_file=text_filename,
                          pii_file=pii_filename)
@app.route('/redact', methods=['POST'])
@login_required(role='customer')
def redact_file():
    pii_to_redact = request.form.getlist('pii_types')
    input_file = request.form['input_file']
    input_path = os.path.join('uploads', input_file)

    redacted_images = []
    images = convert_from_path(input_path)
    for image in images:
        redacted = redact_image(image, pii_to_redact)
        redacted_images.append(redacted.convert('RGB'))

    # Create in-memory PDF
    output_buffer = io.BytesIO()
    redacted_images[0].save(output_buffer, format='PDF', save_all=True, append_images=redacted_images[1:])
    output_buffer.seek(0)
    
    # Generate a unique identifier for the document
    doc_uuid = str(uuid.uuid4())
    
    # Encrypt the redacted PDF
    encryption_key = generate_encryption_key()
    encrypted_data = encrypt_file(output_buffer.read(), encryption_key)
    
    # Store in database
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Insert document
    cur.execute(
        """INSERT INTO documents 
           (uuid, original_filename, encrypted_data, uploaded_by, pii_types) 
           VALUES (%s, %s, %s, %s, %s) RETURNING id""",
        (doc_uuid, input_file, psycopg2.Binary(encrypted_data), session['user_id'], ','.join(pii_to_redact))
    )
    doc_id = cur.fetchone()[0]
    
    # Store encryption key
    cur.execute(
        "INSERT INTO encryption_keys (document_id, key_data) VALUES (%s, %s)",
        (doc_id, psycopg2.Binary(encryption_key))
    )
    
    conn.commit()
    conn.close()
    
    # Create a safe version to download
    temp_output_path = os.path.join('uploads', f'redacted_{input_file}')
    with open(temp_output_path, 'wb') as f:
        redacted_images[0].save(f, format='PDF', save_all=True, append_images=redacted_images[1:])
    
    # Clean up original upload
    if os.path.exists(input_path):
        os.remove(input_path)
    
    flash('Document has been redacted and securely stored.')
    return send_file(temp_output_path, as_attachment=True, download_name=f'redacted_{input_file}')

@app.route('/view_document/<document_uuid>')
@login_required(role=['manager', 'admin'])
def view_document(document_uuid):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Get document and encryption key
    cur.execute("""
        SELECT d.id, d.original_filename, d.encrypted_data, k.key_data 
        FROM documents d
        JOIN encryption_keys k ON d.id = k.document_id
        WHERE d.uuid = %s
    """, (document_uuid,))
    
    doc_data = cur.fetchone()
    conn.close()
    
    if not doc_data:
        flash('Document not found')
        return redirect(url_for('dashboard'))
    
    # Decrypt the document
    decrypted_data = decrypt_file(doc_data['encrypted_data'], doc_data['key_data'])
    
    # Save to temporary file for viewing
    temp_path = os.path.join('uploads', f'temp_{doc_data["original_filename"]}')
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    
    return send_file(temp_path, as_attachment=True, download_name=f'decrypted_{doc_data["original_filename"]}')

# HACKER DEMONSTRATION ROUTE
@app.route('/hack_document/<document_uuid>')
@login_required(role='hacker')
def hack_document(document_uuid):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Get document WITHOUT the encryption key
    cur.execute("""
        SELECT id, original_filename, encrypted_data 
        FROM documents
        WHERE uuid = %s
    """, (document_uuid,))
    
    doc_data = cur.fetchone()
    conn.close()
    
    if not doc_data:
        flash('Document not found')
        return redirect(url_for('dashboard'))
    
    # Save encrypted data directly to file (will be unreadable)
    temp_path = os.path.join('uploads', f'encrypted_{doc_data["original_filename"]}')
    with open(temp_path, 'wb') as f:
        f.write(doc_data['encrypted_data'])
    
    flash('Access attempt recorded! You do not have decryption keys for this document.')
    return send_file(temp_path, as_attachment=True, download_name=f'encrypted_{doc_data["original_filename"]}')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/demo')
def security_demo():
    """Route to demonstrate the security differences between manager and hacker access"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    return render_template('security_demo.html')

@app.before_request
def check_first_run():
    if request.endpoint != 'static':
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
        except psycopg2.OperationalError:
            flash('Database connection failed. Please check configuration.')
            return render_template('error.html', error="Database connection failed")

if __name__ == '__main__':
    try:
        init_db()
        app.run(debug=True)
    except Exception as e:
        print(f"Failed to initialize: {e}")