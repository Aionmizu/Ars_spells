import os
import hashlib
import sqlite3
import stat
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, g, jsonify, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
# Use /data directory for database if available (for Render.com deployment)
if os.path.exists('/data'):
    app.config['DATABASE'] = '/data/combos.db'
else:
    app.config['DATABASE'] = os.path.join(app.root_path, 'combos.db')

# Secret key for session management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_for_development_only')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize password hasher
ph = PasswordHasher()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @staticmethod
    def get(user_id):
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user is None:
            return None
        return User(user['id'], user['username'], user['password'])

    @staticmethod
    def get_by_username(username):
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user is None:
            return None
        return User(user['id'], user['username'], user['password'])

    @staticmethod
    def create(username, password):
        db = get_db()
        hashed_password = ph.hash(password)
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                      (username, hashed_password))
            db.commit()
            return True
        except sqlite3.IntegrityError:
            # Username already exists
            return False

    def verify_password(self, password):
        try:
            ph.verify(self.password, password)
            return True
        except VerifyMismatchError:
            return False

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def set_db_permissions():
    """Set the database file permissions to 600 (read/write for owner only)"""
    try:
        # This will work on Unix-like systems (Linux, macOS)
        if os.name == 'posix':
            os.chmod(app.config['DATABASE'], stat.S_IRUSR | stat.S_IWUSR)
            app.logger.info(f"Set permissions 600 on {app.config['DATABASE']}")
    except Exception as e:
        app.logger.warning(f"Could not set file permissions: {e}")

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row

        # Enable WAL mode for better concurrency
        db.execute("PRAGMA journal_mode=WAL;")

        # Set busy timeout to 5000ms (5 seconds)
        db.execute("PRAGMA busy_timeout=5000;")

        # Ensure foreign keys are enforced
        db.execute("PRAGMA foreign_keys=ON;")
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.executescript(f.read())
        db.commit()
        # Set proper permissions on the database file
        set_db_permissions()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def cleanup_old_votes():
    """Delete votes older than 30 days to keep the database size manageable"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM votes WHERE voted_at < DATE('now', '-30 days')")
    deleted_count = cursor.rowcount
    db.commit()
    if deleted_count > 0:
        app.logger.info(f"Deleted {deleted_count} old votes")
    return deleted_count

def check_patched_status():
    db = get_db()
    cursor = db.cursor()

    # Update patched status based on patched reports (3+ reports in the last month)
    cursor.execute("""
    UPDATE combos
    SET patched = 1
    WHERE id IN (
        SELECT combo_id
        FROM reports
        WHERE report_type = 'patched'
          AND reported_at >= datetime('now', '-30 days')
        GROUP BY combo_id
        HAVING COUNT(*) >= 3
    )
    """)

    # Delete combos with 5+ inappropriate reports
    cursor.execute("""
    DELETE FROM combos
    WHERE id IN (
        SELECT combo_id
        FROM reports
        WHERE report_type = 'inappropriate'
          AND reported_at >= datetime('now', '-30 days')
        GROUP BY combo_id
        HAVING COUNT(*) >= 5
    )
    """)

    # Also clean up old votes
    cleanup_old_votes()

    db.commit()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        if User.get_by_username(username):
            flash('Username already exists', 'error')
            return render_template('register.html')

        if User.create(username, password):
            user = User.get_by_username(username)
            login_user(user)
            flash('Registration successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Registration failed', 'error')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.get_by_username(username)
        if user and user.verify_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/privacy')
def privacy():
    # Pass the current date as the last updated date
    last_updated = datetime.now().strftime('%B %d, %Y')
    return render_template('privacy.html', last_updated=last_updated)

@app.route('/')
def index():
    db = get_db()
    search_query = request.args.get('search', '')

    if search_query:
        # Search in name, spells, description, tags
        query = """
        SELECT * FROM combos 
        WHERE name LIKE ? 
           OR spells LIKE ? 
           OR description LIKE ? 
           OR tags LIKE ? 
        ORDER BY created_at DESC
        """
        search_param = f'%{search_query}%'
        combos = db.execute(query, (search_param, search_param, search_param, search_param)).fetchall()
    else:
        combos = db.execute("SELECT * FROM combos ORDER BY created_at DESC").fetchall()

    return render_template('index.html', combos=combos, search_query=search_query)

@app.route('/profile/<username>')
def profile(username):
    db = get_db()
    # Get all combos created by the user
    combos = db.execute("SELECT * FROM combos WHERE creator = ? ORDER BY created_at DESC", (username,)).fetchall()
    return render_template('profile.html', username=username, combos=combos)

@app.route('/edit/<int:cid>', methods=['GET', 'POST'])
@login_required
def edit_combo(cid):
    db = get_db()
    combo = db.execute("SELECT * FROM combos WHERE id = ?", (cid,)).fetchone()

    if combo is None:
        flash('Combo not found', 'error')
        return redirect(url_for('index'))

    # Check if the current user is the creator of the combo
    if combo['creator'] != current_user.username:
        flash('You can only edit your own combos', 'error')
        return redirect(url_for('profile', username=current_user.username))

    if request.method == 'POST':
        data = request.form

        # Update the combo
        db.execute("""
            UPDATE combos
            SET name = ?, spells = ?, description = ?, requirement = ?, tags = ?, creator = ?
            WHERE id = ?
        """, (
            data['name'], 
            data['spells'], 
            data['description'],
            data['requirement'], 
            data['tags'], 
            data['creator'],
            cid
        ))
        db.commit()

        flash('Combo updated successfully', 'success')
        return redirect(url_for('profile', username=current_user.username))

    return render_template('edit_spell.html', combo=combo)

@app.route('/delete/<int:cid>', methods=['DELETE'])
@login_required
def delete_combo(cid):
    db = get_db()
    combo = db.execute("SELECT * FROM combos WHERE id = ?", (cid,)).fetchone()

    if combo is None:
        return jsonify({'error': 'Combo not found'}), 404

    # Check if the current user is the creator of the combo
    if combo['creator'] != current_user.username:
        return jsonify({'error': 'You can only delete your own combos'}), 403

    # Delete the combo
    db.execute("DELETE FROM combos WHERE id = ?", (cid,))
    db.commit()

    return '', 204

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_combo():
    if request.method == 'POST':
        db = get_db()
        data = request.form

        # Use the creator from the form if provided, otherwise use the current user's username
        creator = data.get('creator') or current_user.username

        db.execute("""INSERT INTO combos
                      (name, spells, description, requirement, tags, creator)
                      VALUES (?,?,?,?,?,?)""",
                   (data['name'], data['spells'], data['description'],
                    data['requirement'], data['tags'], creator))
        db.commit()
        check_patched_status()
        return redirect(url_for('index'))
    return render_template('form.html')

@app.post('/api/combos')
@login_required
def api_add_combo():
    db = get_db()
    data = request.form

    # Use the creator from the form if provided, otherwise use the current user's username
    creator = data.get('creator') or current_user.username

    db.execute("""INSERT INTO combos
                  (name, spells, description, requirement, tags, creator)
                  VALUES (?,?,?,?,?,?)""",
               (data['name'], data['spells'], data['description'],
                data['requirement'], data['tags'], creator))
    db.commit()
    check_patched_status()
    return '', 204

@app.post('/api/combos/<int:cid>/vote')
def vote(cid):
    db = get_db()
    vote = int(request.form['vote'])        # 0 or 1
    h = hashlib.sha256(request.remote_addr.encode()).hexdigest()
    try:
        db.execute("INSERT INTO votes (combo_id, vote, voter_hash) VALUES (?,?,?)",
                   (cid, vote, h))
        db.commit()
        check_patched_status()
    except sqlite3.IntegrityError:
        pass  # duplicate vote ignored
    return '', 204

@app.route('/api/combos/<int:cid>/rating')
def get_rating(cid):
    db = get_db()
    # Calculate the rating (percentage of positive votes)
    votes = db.execute("""
        SELECT vote FROM votes WHERE combo_id = ?
    """, (cid,)).fetchall()

    total_votes = len(votes)
    if total_votes == 0:
        rating = "No votes"
    else:
        positive_votes = sum(v['vote'] for v in votes)
        rating = f"{positive_votes * 10 // total_votes}/10 ({total_votes} votes)"

    return render_template('rating_snippet.html', rating=rating, combo_id=cid)

@app.post('/api/combos/<int:cid>/report')
def report(cid):
    db = get_db()
    report_type = request.form.get('type')

    if report_type not in ['inappropriate', 'patched']:
        return jsonify({'error': 'Invalid report type'}), 400

    h = hashlib.sha256(request.remote_addr.encode()).hexdigest()

    try:
        db.execute("""
            INSERT INTO reports (combo_id, report_type, reporter_hash) 
            VALUES (?, ?, ?)
        """, (cid, report_type, h))
        db.commit()
        check_patched_status()
        return '', 204
    except sqlite3.IntegrityError:
        # User already reported this combo with this type
        return jsonify({'error': 'Already reported'}), 409

def ensure_table_exists(table_name, create_script, log_message):
    """Check if a table exists and create it if it doesn't"""
    db = get_db()
    # Check if the table exists
    result = db.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'").fetchone()
    if result is None:
        # Table doesn't exist, create it
        db.executescript(create_script)
        db.commit()
        app.logger.info(log_message)

def ensure_users_table_exists():
    """Check if the users table exists and create it if it doesn't"""
    create_script = """
    -- users table for authentication
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Create index for faster user queries
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    """
    ensure_table_exists('users', create_script, "Created missing users table")

def ensure_reports_table_exists():
    """Check if the reports table exists and create it if it doesn't"""
    create_script = """
    -- reports table for tracking inappropriate and patched reports
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        combo_id INTEGER,
        report_type TEXT CHECK(report_type IN ('inappropriate', 'patched')),
        reporter_hash TEXT,                         -- hash(IP)
        reported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(combo_id, reporter_hash, report_type), -- 1 report of each type per machine
        FOREIGN KEY (combo_id) REFERENCES combos(id)
    );

    -- Create index for faster report queries
    CREATE INDEX IF NOT EXISTS idx_reports_combo_id ON reports(combo_id);
    CREATE INDEX IF NOT EXISTS idx_reports_reported_at ON reports(reported_at);
    CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
    """
    ensure_table_exists('reports', create_script, "Created missing reports table")

# Initialize the database at startup
with app.app_context():
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    else:
        # Ensure the users and reports tables exist in an existing database
        ensure_users_table_exists()
        ensure_reports_table_exists()

if __name__ == '__main__':
    app.run(debug=True)
