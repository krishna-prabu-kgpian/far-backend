from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change for production

# Enable CORS with credentials support so that cookies work across origins.
CORS(app, supports_credentials=True)

DATABASE = 'users.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    # Updated schema with new profile fields
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            email TEXT,
            mobile TEXT,
            cg REAL,
            interests TEXT,
            linkedin_url TEXT,
            github_url TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Check if username already exists
    conn = get_db()
    existing_user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing_user:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400

    if len(password) < 8:
        conn.close()
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400

    if password != confirm_password:
        conn.close()
        return jsonify({'error': 'Passwords do not match'}), 400

    

    hashed_password = generate_password_hash(password)
    try:
        conn.execute(
            "INSERT INTO users (username, password, name, email, mobile, cg, interests, linkedin_url, github_url) VALUES (?, ?, '', '', '', NULL, '', '', '')",
            (username, hashed_password)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'An error occurred during signup'}), 400
    finally:
        conn.close()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        return jsonify({'message': 'Logged in successfully'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/profile', methods=['GET'])
def get_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()

    try:
        interests = json.loads(user['interests']) if user['interests'] else []
    except Exception:
        interests = []

    return jsonify({
        'username': user['username'],
        'name': user['name'] or "",
        'email': user['email'] or "",
        'mobile': user['mobile'] or "",
        'cg': user['cg'] if user['cg'] is not None else "",
        'interests': interests,
        'linkedin_url': user['linkedin_url'] or "",
        'github_url': user['github_url'] or ""
    }), 200

@app.route('/api/profile', methods=['PUT'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    name = data.get('name', '')
    email = data.get('email', '')
    mobile = data.get('mobile', '')
    cg = data.get('cg', '')
    linkedin_url = data.get('linkedin_url', '')
    github_url = data.get('github_url', '')
    interests = data.get('interests', [])
    interests_str = json.dumps(interests)

    # Validate mobile: must be exactly 10 digits
    if mobile and (len(mobile) != 10 or not mobile.isdigit()):
        return jsonify({'error': 'Mobile number must be exactly 10 digits'}), 400

    # Validate CG: must be a float between 0 and 10
    try:
        cg_val = float(cg) if cg != "" else None
        if cg_val is not None and (cg_val < 0 or cg_val > 10):
            return jsonify({'error': 'CG must be between 0 and 10'}), 400
    except ValueError:
        return jsonify({'error': 'CG must be a number'}), 400

    conn = get_db()
    conn.execute('''
        UPDATE users 
        SET name = ?, email = ?, mobile = ?, cg = ?, interests = ?, linkedin_url = ?, github_url = ?
        WHERE id = ?
    ''', (name, email, mobile, cg_val, interests_str, linkedin_url, github_url, session['user_id']))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Profile updated successfully'}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)
