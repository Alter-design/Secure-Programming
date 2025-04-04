from flask import Flask, render_template, request, redirect, url_for, session, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions

DATABASE = 'member.db'

# Users with hashed passwords
USERS = {
    "staff": {"password": generate_password_hash("staffpass"), "role": "staff"},
    "member": {"password": generate_password_hash("memberpass"), "role": "member"},
    "pakkarim": {"password": generate_password_hash("karim"), "role": "staff"}
}

# Database Connection Helper
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Return dictionary-like results
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False, commit=False):
    db = get_db()
    cur = db.execute(query, args)
    if commit:
        db.commit()
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Create Tables Once (Not Before Every Request)
def create_db():
    db = get_db()
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
                member_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                FOREIGN KEY(member_id) REFERENCES members(id),
                FOREIGN KEY(class_id) REFERENCES classes(id)
               )''')
    db.commit()

# Session Timeout Handling
SESSION_TIMEOUT = 3600  # 1 hour

@app.before_request
def check_session_timeout():
    if 'last_activity' in session:
        elapsed_time = time.time() - session['last_activity']
        if elapsed_time > SESSION_TIMEOUT:
            session.clear()
            abort(401)  # Unauthorized instead of redirect to avoid errors
    session['last_activity'] = time.time()

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in USERS and check_password_hash(USERS[username]['password'], password):
            session['user'] = username
            session['role'] = USERS[username]['role']
            return redirect(url_for('dashboard'))
        else:
            return "Login Failed!"
    return render_template('login.html')

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)

# View Classes Route (FIXED)
@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        name = request.form['name']
        status = request.form["status"]
        query_db("INSERT INTO members (name, membership_status) VALUES (?,?)", (name, status), commit=True)
        return redirect(url_for('view_members'))
                                 
    return render_template('add_member.html')

# Register class and view member classes
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        query_db("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id), commit=True)
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        query_db("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status), commit=True)
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# View members and manage members
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

@app.route('/member_classes/<int:member_id>')
def member_classes(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    # Query to get the member's registered classes
    member_classes = query_db("""
        SELECT c.class_name, c.class_time 
        FROM classes c 
        JOIN member_classes mc ON c.id = mc.class_id
        WHERE mc.member_id = ?
    """, (member_id,))
    
    return render_template('member_classes.html', member_id=member_id, member_classes=member_classes)

@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    # Your delete logic here
    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    with app.app_context():
        create_db()  # Ensure database is set up before running
    app.run(debug=True)
