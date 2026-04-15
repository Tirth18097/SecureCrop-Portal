from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import hashlib, sqlite3, base64, os
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

from twilio.rest import Client as TwilioClient

# ---- Load environment variables from .env ----
load_dotenv()

import re
def strip_ansi(text):
    """Remove ANSI terminal color codes from Twilio error strings."""
    return re.sub(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', str(text))

TWILIO_ACCOUNT_SID  = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN   = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_VERIFY_SID   = os.getenv('TWILIO_VERIFY_SID')

twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

app = Flask(__name__)

# ---- Global JSON error handler so Flask never returns HTML to the API ----
@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    traceback.print_exc()   # print to Flask terminal for debugging
    return jsonify({'success': False, 'error': str(e)}), 500
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'agrosecure-fallback-secret')

# ================================================================
# DATABASE SETUP
# ================================================================
def init_db():
    conn = sqlite3.connect('crop_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS crop_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        farmer_name TEXT, encrypted_data TEXT,
        aes_key TEXT, aes_iv TEXT, sha256_hash TEXT,
        digital_signature TEXT, public_key TEXT, timestamp TEXT
    )''')
    conn.commit(); conn.close()

init_db()

# ================================================================
# AUTH HELPERS
# ================================================================
def login_required(f):
    """Decorator — redirects to login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ================================================================
# CRYPTOGRAPHY HELPERS
# ================================================================
def aes_encrypt(data: str):
    key = os.urandom(16)
    iv  = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(ct).decode(), base64.b64encode(key).decode(), base64.b64encode(iv).decode()

def aes_decrypt(enc_data, key_b64, iv_b64):
    key, iv, ct = base64.b64decode(key_b64), base64.b64decode(iv_b64), base64.b64decode(enc_data)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def generate_rsa_keys():
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv = pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub  = pk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub

def sign_data(data, priv_pem):
    pk = serialization.load_pem_private_key(priv_pem.encode(), password=None, backend=default_backend())
    return base64.b64encode(pk.sign(data.encode(), asym_padding.PKCS1v15(), hashes.SHA256())).decode()

def verify_signature(data, sig_b64, pub_pem):
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
        pub.verify(base64.b64decode(sig_b64), data.encode(), asym_padding.PKCS1v15(), hashes.SHA256())
        return True
    except:
        return False

# ================================================================
# AUTH ROUTES
# ================================================================

@app.route('/login')
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    """Send OTP via Twilio Verify."""
    try:
        body  = request.get_json(force=True, silent=True) or {}
        phone = body.get('phone', '').strip()
        role  = body.get('role', 'farmer')

        if not phone or len(phone) < 10:
            return jsonify({'success': False, 'error': 'Invalid phone number.'})

        print(f"[OTP] Sending to {phone} (role={role}) via Verify SID={TWILIO_VERIFY_SID}")

        twilio_client.verify.v2.services(TWILIO_VERIFY_SID) \
            .verifications.create(to=phone, channel='sms')

        session['pending_phone'] = phone
        session['pending_role']  = role
        print(f"[OTP] Successfully sent to {phone}")
        return jsonify({'success': True})

    except Exception as e:
        import traceback; traceback.print_exc()
        error_msg = strip_ansi(str(e))
        if 'unverified' in error_msg.lower() or '60203' in error_msg:
            error_msg = '⚠️ This number is not verified on your Twilio trial account. Only +91 98920 92952 can receive OTPs.'
        elif '20404' in error_msg:
            error_msg = '⚠️ Twilio Verify Service not found. Please check your TWILIO_VERIFY_SID in the .env file.'
        return jsonify({'success': False, 'error': error_msg})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP entered by the user."""
    try:
        body  = request.get_json(force=True, silent=True) or {}
        phone = body.get('phone', '').strip()
        otp   = body.get('otp', '').strip()
        role  = body.get('role', 'farmer')

        if not phone or not otp:
            return jsonify({'success': False, 'error': 'Phone and OTP are required.'})

        print(f"[OTP] Verifying code for {phone}")
        result = twilio_client.verify.v2.services(TWILIO_VERIFY_SID) \
            .verification_checks.create(to=phone, code=otp)

        if result.status == 'approved':
            session['logged_in'] = True
            session['user_phone'] = phone
            session['user_role']  = role
            session.pop('pending_phone', None)
            session.pop('pending_role',  None)
            redirect_url = '/farmer' if role == 'farmer' else '/department'
            print(f"[OTP] Verified! Role={role}")
            return jsonify({'success': True, 'redirect': redirect_url, 'role': role})
        else:
            return jsonify({'success': False, 'error': 'Incorrect OTP. Please try again.'})

    except Exception as e:
        import traceback; traceback.print_exc()
        error_msg = str(e)
        if '20404' in error_msg:
            error_msg = 'OTP expired or not found. Please request a new one.'
        return jsonify({'success': False, 'error': error_msg})

# ================================================================
# MAIN PAGE
# ================================================================

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/farmer')
@login_required
def farmer_portal():
    return render_template('farmer.html')

@app.route('/department')
@login_required
def department_portal():
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_login'))
    return render_template('department.html')

@app.route('/admin-login')
@login_required
def admin_login():
    if session.get('admin_authenticated'):
        return redirect(url_for('department_portal'))
    return render_template('admin_login.html')

@app.route('/api/admin-login', methods=['POST'])
@login_required
def api_admin_login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get('username', '').strip()
    password = body.get('password', '')
    if username == 'admin' and password == '1234':
        session['admin_authenticated'] = True
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Invalid username or password.'})

# ================================================================
# CROP DATA API ROUTES
# ================================================================

@app.route('/api/encrypt', methods=['POST'])
@login_required
def encrypt_route():
    body        = request.json
    farmer_name = body.get('farmer_name', 'Unknown')
    crop_data   = body.get('crop_data', '')
    data_hash   = sha256_hash(crop_data)
    encrypted, aes_key, aes_iv = aes_encrypt(crop_data)
    priv, pub   = generate_rsa_keys()
    signature   = sign_data(crop_data, priv)
    conn = sqlite3.connect('crop_data.db'); c = conn.cursor()
    c.execute('INSERT INTO crop_records (farmer_name,encrypted_data,aes_key,aes_iv,sha256_hash,digital_signature,public_key,timestamp) VALUES (?,?,?,?,?,?,?,?)',
        (farmer_name, encrypted, aes_key, aes_iv, data_hash, signature, pub, datetime.now().isoformat()))
    rid = c.lastrowid; conn.commit(); conn.close()
    return jsonify({
        'success': True, 'record_id': rid,
        'encrypted_data': encrypted[:60] + '...',
        'sha256_hash': data_hash,
        'signature_preview': signature[:60] + '...',
        'steps': [
            'Crop data received from farmer portal',
            'SHA-256 hash generated for integrity verification',
            'AES-128 encryption applied (CBC mode, random IV)',
            'RSA-2048 digital signature created with private key',
            f'Record #{rid} stored securely in database'
        ]
    })

@app.route('/api/decrypt/<int:record_id>')
@login_required
def decrypt_route(record_id):
    conn = sqlite3.connect('crop_data.db'); c = conn.cursor()
    c.execute('SELECT * FROM crop_records WHERE id=?', (record_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return jsonify({'success': False, 'error': 'Record not found'})
    _, farmer, enc, key, iv, stored_hash, sig, pub, ts = row
    decrypted = aes_decrypt(enc, key, iv)
    integrity = sha256_hash(decrypted) == stored_hash
    sig_valid = verify_signature(decrypted, sig, pub)
    return jsonify({
        'success': True, 'farmer_name': farmer,
        'decrypted_data': decrypted,
        'integrity_check': integrity,
        'signature_valid': sig_valid,
        'timestamp': ts,
        'steps': [
            f'Record #{record_id} retrieved from database',
            'AES-128 decryption applied using stored key + IV',
            f'SHA-256 integrity: {"✅ PASSED — data unmodified" if integrity else "❌ FAILED — tampered!"}',
            f'RSA-2048 signature: {"✅ VERIFIED — authentic" if sig_valid else "❌ INVALID"}',
            'Original crop data restored successfully'
        ]
    })

@app.route('/api/records')
@login_required
def get_records():
    conn = sqlite3.connect('crop_data.db'); c = conn.cursor()
    c.execute('SELECT id,farmer_name,sha256_hash,timestamp FROM crop_records ORDER BY id DESC')
    rows = c.fetchall(); conn.close()
    return jsonify([{'id': r[0], 'farmer': r[1], 'hash': r[2][:20] + '...', 'timestamp': r[3]} for r in rows])


@app.route('/api/records/<int:record_id>', methods=['DELETE'])
@login_required
def delete_record(record_id):
    """Delete a crop record by ID."""
    try:
        conn = sqlite3.connect('crop_data.db'); c = conn.cursor()
        c.execute('SELECT id FROM crop_records WHERE id=?', (record_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': f'Record #{record_id} not found.'})
        c.execute('DELETE FROM crop_records WHERE id=?', (record_id,))
        conn.commit(); conn.close()
        print(f'[DB] Deleted record #{record_id}')
        return jsonify({'success': True, 'message': f'Record #{record_id} deleted.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ================================================================
# USER INFO API (for optional use in frontend)
# ================================================================

@app.route('/api/me')
@login_required
def get_me():
    return jsonify({
        'phone': session.get('user_phone'),
        'role':  session.get('user_role')
    })

if __name__ == '__main__':
    app.run(debug=True)
