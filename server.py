from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for, session
import os
import pyotp
import qrcode
import sqlite3
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(32)  # for session management

# SQLite database setup
def get_db():
    db = sqlite3.connect('users.db')
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            totp_secret TEXT,
            webauthn_credential BLOB
        )''')
        db.commit()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user:
            return render_template('register.html', error="Username already exists")
        
        # TODO: Task 1 - Implement secure password hashing
        # Instead of storing the password directly, hash it using a secure method
        # Hint: Use hashlib.sha256() and add a salt
        hashed_password = password  # Replace this line with your implementation
        
        assert hashed_password != password, "Make sure to hash the password before storing it"

        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if not user:
            return render_template('login.html', error="User not found")
        
        # TODO: Task 2 - Implement secure password verification
        # Compare the hashed version of the input password with the stored hash
        # Hint: Use the same hashing method as in the register function
        hashed_password = user['password']  # Replace this line with your implementation

        assert hashed_password != user['password'], "Make sure to hash the password before checking it"

        if hashed_password == user['password']:  # Replace this line with your implementation
            if user['totp_secret']:
                session['pending_login_username'] = username
                return redirect(url_for('enter_totp'))
            else:
                session['username'] = username
                return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid password")
    
    return render_template('login.html')

@app.route('/enter_totp', methods=['GET', 'POST'])
def enter_totp():
    if 'pending_login_username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        totp_code = request.form.get('totp_code')
        username = session['pending_login_username']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if not user or not user['totp_secret']:
            return redirect(url_for('login'))

        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(totp_code):
            session.pop('pending_login_username', None)
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('enter_totp.html', error="Invalid TOTP code")

    return render_template('enter_totp.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = session['username']
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        # TODO: Task 3 - Implement password change functionality
        # Verify the old password, then update with the new password
        # Remember to hash the new password before storing it
        hashed_new_password = None  # Replace this line with proper hashing

        assert hashed_new_password, "Make sure to hash the new password before storing it"
        db.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_new_password, username))
        db.commit()

        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/generate_totp_secret', methods=['GET', 'POST'])
def generate_totp_secret():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = session['username']
        
        # TODO: Task 4 - Implement TOTP secret generation
        # Generate a random secret for TOTP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
        totp_secret = None  # Replace this line with proper secret generation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
        assert totp_secret, "Make sure to generate a random secret for TOTP"

        # Store the secret temporarily in the session
        session['temp_totp_secret'] = totp_secret

        # Generate QR code
        totp = pyotp.TOTP(totp_secret)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp.provisioning_uri(username, issuer_name="S3KC Auth Demo"))
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        return send_file(img_io, mimetype='image/png')
    
    return render_template('generate_totp.html')

@app.route('/verify_totp', methods=['POST'])
def verify_totp():
    if 'username' not in session or 'temp_totp_secret' not in session:
        return jsonify({"status": "error", "message": "No active TOTP setup session"}), 400

    username = session['username']
    totp_secret = session['temp_totp_secret']
    
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"status": "error", "message": "No TOTP code provided"}), 400

    totp = pyotp.TOTP(totp_secret)
    if totp.verify(data['code']):
        # TOTP verified, save the secret to the database
        db = get_db()
        db.execute('UPDATE users SET totp_secret = ? WHERE username = ?', (totp_secret, username))
        db.commit()
        
        # Clear the temporary secret from the session
        session.pop('temp_totp_secret', None)
        
        return jsonify({"status": "success", "message": "TOTP verified and saved"})
    else:
        return jsonify({"status": "error", "message": "Invalid TOTP code"}), 400

if __name__ == '__main__':
    app.run(debug=True)
