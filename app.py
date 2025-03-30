from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # Auto logout after 30 minutes
csrf = CSRFProtect(app)

DATABASE = 'member.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, 
                username TEXT UNIQUE NOT NULL, 
                password TEXT NOT NULL, 
                role TEXT NOT NULL
               )''')
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY, 
                name TEXT NOT NULL, 
                membership_status TEXT NOT NULL
               )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY, 
                class_name TEXT NOT NULL, 
                class_time TEXT NOT NULL
               )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                id INTEGER PRIMARY KEY, 
                member_id INTEGER, 
                class_id INTEGER,
                FOREIGN KEY (member_id) REFERENCES members(id),
                FOREIGN KEY (class_id) REFERENCES classes(id)
               )''')
    db.commit()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return "Login Failed!"
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    return render_template('add_member.html')

@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    db = get_db()
    db.execute("DELETE FROM members WHERE id = ?", (member_id,))
    db.execute("DELETE FROM member_classes WHERE member_id = ?", (member_id,))
    db.commit()
    return redirect(url_for('view_members'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
