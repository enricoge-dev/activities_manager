import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta # Import date for default date picker value

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a strong, random key in production
DATABASE = 'database.db'


def get_db():
    """Connects to the specific database."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # This makes rows behave like dicts
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def login_required(f):
    """Decorator to check if user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to check if user is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_user_id_from_session():
    """Helper to get the current user's ID."""
    db = get_db()
    user = db.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()
    return user['id'] if user else None


def get_all_activity_tags():
    """Helper to get all unique activity tags for datalist suggestions."""
    db = get_db()
    tags = db.execute('SELECT tag_name FROM activity_tags ORDER BY tag_name').fetchall()
    return [tag['tag_name'] for tag in tags]


def add_activity_tag_if_new(tag_name):
    """Helper to add a new activity tag if it doesn't already exist."""
    db = get_db()
    try:
        db.execute('INSERT INTO activity_tags (tag_name) VALUES (?)', (tag_name,))
        db.commit()
    except sqlite3.IntegrityError:
        # Tag already exists, do nothing
        pass


@app.route('/')
def index():
    """Redirects to the login page if no specific endpoint is provided."""
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Invalid credentials.'
        elif not check_password_hash(user['password_hash'], password):
            error = 'Invalid credentials.'

        if error is None:
            session.clear()
            session['logged_in'] = True
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')

            if user['must_change_password']:
                return redirect(url_for('change_password'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash(error, 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """A protected page accessible only after login."""
    return render_template('dashboard.html', username=session['username'], role=session['role'])


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allows user to change their password, especially for first-time login."""
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?', (session['username'],)
    ).fetchone()

    if not user or not user['must_change_password']:
        # If user is not found or not required to change password, redirect
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        error = None

        if not check_password_hash(user['password_hash'], old_password):
            error = 'Incorrect old password.'
        elif new_password != confirm_password:
            error = 'New passwords do not match.'
        elif len(new_password) < 6: # Basic password strength check
            error = 'New password must be at least 6 characters long.'

        if error is None:
            db.execute(
                'UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
                (generate_password_hash(new_password), user['id'])
            )
            db.commit()
            flash('Password changed successfully! You can now proceed.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(error, 'danger')

    return render_template('change_password.html', username=session['username'], role=session['role'])


@app.route('/admin/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    """Allows admin to create new standard users."""
    db = get_db()
    if request.method == 'POST':
        username = request.form['username']
        password = 'pass' # Default password for new users
        error = None

        if not username:
            error = 'Username is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            error = f"User {username} already exists."

        if error is None:
            hashed_password = generate_password_hash(password)
            db.execute(
                'INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, ?)',
                (username, hashed_password, 'standard', 1)
            )
            db.commit()
            flash(f'User {username} created successfully with default password "pass".', 'success')
            return redirect(url_for('admin_users')) # Redirect to user list after creation
        else:
            flash(error, 'danger')

    return render_template('create_user.html', username=session['username'], role=session['role'])


@app.route('/admin/users')
@admin_required
def admin_users():
    """Displays a list of all users for admin management."""
    db = get_db()
    users = db.execute('SELECT id, username, role, must_change_password FROM users').fetchall()
    return render_template('user_list.html', users=users, username=session['username'], role=session['role'])


# --- New routes for selected users ---

@app.route('/admin/delete_selected_users', methods=['POST'])
@admin_required
def delete_selected_users():
    """Deletes selected users."""
    user_ids = request.form.getlist('user_ids')
    db = get_db()
    deleted_count = 0
    for user_id in user_ids:
        user_to_delete = db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_to_delete and user_to_delete['username'] == session['username']:
            flash(f"Cannot delete your own account ({user_to_delete['username']}).", 'danger')
        else:
            db.execute('DELETE FROM users WHERE id = ?', (user_id,))
            deleted_count += 1
    db.commit()
    if deleted_count > 0:
        flash(f"{deleted_count} user(s) deleted successfully.", 'success')
    else:
        flash("No users selected for deletion or unable to delete.", 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/toggle_selected_admin', methods=['POST'])
@admin_required
def toggle_selected_admin():
    """Toggles admin status for selected users."""
    user_ids = request.form.getlist('user_ids')
    db = get_db()
    toggled_count = 0
    for user_id in user_ids:
        user_to_toggle = db.execute('SELECT username, role FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_to_toggle and user_to_toggle['username'] == session['username']:
            flash(f"Cannot change your own admin status ({user_to_toggle['username']}).", 'danger')
        else:
            new_role = 'standard' if user_to_toggle['role'] == 'admin' else 'admin'
            db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
            toggled_count += 1
    db.commit()
    if toggled_count > 0:
        flash(f"{toggled_count} user(s) admin status toggled successfully.", 'success')
    else:
        flash("No users selected for role change or unable to change.", 'info')
    return redirect(url_for('admin_users'))


@app.route('/admin/reset_selected_passwords', methods=['POST'])
@admin_required
def reset_selected_passwords():
    """Resets passwords for selected users to default 'pass' and forces password change."""
    user_ids = request.form.getlist('user_ids')
    db = get_db()
    reset_count = 0
    default_hashed_password = generate_password_hash('pass')
    for user_id in user_ids:
        user_to_reset = db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_to_reset and user_to_reset['username'] == session['username']:
            flash(f"Cannot reset your own password ({user_to_reset['username']}).", 'danger')
        else:
            db.execute(
                'UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?',
                (default_hashed_password, user_id)
            )
            reset_count += 1
    db.commit()
    if reset_count > 0:
        flash(f"{reset_count} user(s) password(s) reset to default 'pass'. They must change it on next login.", 'success')
    else:
        flash("No users selected for password reset or unable to reset.", 'info')
    return redirect(url_for('admin_users'))


# --- Event Management Routes ---
@app.route('/add_event', methods=['GET', 'POST'])
@login_required
def add_event():
    """Handles adding new events."""
    db = get_db()
    if request.method == 'POST':
        event_date = request.form['event_date']
        start_times = request.form.getlist('start_time')
        end_times = request.form.getlist('end_time')
        notes = request.form.getlist('note')
        activity_tags = request.form.getlist('activity_tag')

        user_id = get_user_id_from_session()
        if not user_id:
            flash("User not found.", 'danger')
            return redirect(url_for('dashboard'))

        if not event_date:
            flash("Event date is required.", 'danger')
            return render_template('add_event.html', today_date=date.today().isoformat(), activity_tags=get_all_activity_tags(), username=session['username'], role=session['role'])

        # Insert event
        cursor = db.execute('INSERT INTO events (user_id, event_date) VALUES (?, ?)', (user_id, event_date))
        event_id = cursor.lastrowid

        # Insert intervals
        for i in range(len(start_times)):
            start_time = start_times[i]
            end_time = end_times[i]
            note = notes[i].strip()
            activity_tag = activity_tags[i].strip()

            if not start_time or not end_time or not activity_tag:
                flash(f"Interval {i+1}: Start time, end time, and activity tag are required.", 'danger')
                # Consider rolling back the event insertion or handling more gracefully
                db.rollback() # Rollback the event insertion if an interval is invalid
                return render_template('add_event.html', today_date=date.today().isoformat(), activity_tags=get_all_activity_tags(), username=session['username'], role=session['role'])

            if len(note) > 10:
                flash(f"Interval {i+1}: Note must be max 10 characters.", 'danger')
                db.rollback()
                return render_template('add_event.html', today_date=date.today().isoformat(), activity_tags=get_all_activity_tags(), username=session['username'], role=session['role'])

            # Add tag to activity_tags table if new
            add_activity_tag_if_new(activity_tag)

            db.execute(
                'INSERT INTO intervals (event_id, start_time, end_time, note, activity_tag) VALUES (?, ?, ?, ?, ?)',
                (event_id, start_time, end_time, note, activity_tag)
            )
        db.commit()
        flash('Event added successfully!', 'success')
        return redirect(url_for('add_event')) # Redirect to clear form

    # GET request
    activity_tags_list = get_all_activity_tags()
    return render_template('add_event.html', today_date=date.today().isoformat(), activity_tags=activity_tags_list, username=session['username'], role=session['role'])


@app.route('/list_events')
@login_required
def list_events():
    """Displays a list of all events for the current user."""
    db = get_db()
    user_id = get_user_id_from_session()
    if not user_id:
        flash("User not found.", 'danger')
        return redirect(url_for('dashboard'))

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Base query
    query = (
        'SELECT e.event_date, i.id, i.start_time, i.end_time, i.note, i.activity_tag '
        'FROM events e JOIN intervals i ON e.id = i.event_id '
        'WHERE e.user_id = ?'
    )
    params = [user_id]

    # Add date range filter if provided
    if start_date and end_date:
        query += ' AND e.event_date BETWEEN ? AND ?'
        params.extend([start_date, end_date])

    query += ' ORDER BY e.event_date DESC, i.start_time ASC'

    events_query = db.execute(query, tuple(params)).fetchall()

    intervals = []
    total_duration = 0
    activity_tags = set()
    for row in events_query:
        activity_tags.add(row['activity_tag'])
        start_time_obj = datetime.strptime(row['start_time'], '%H:%M').time()
        end_time_obj = datetime.strptime(row['end_time'], '%H:%M').time()

        dummy_date = date(1, 1, 1)
        start_datetime = datetime.combine(dummy_date, start_time_obj)
        end_datetime = datetime.combine(dummy_date, end_time_obj)

        if end_datetime < start_datetime:
            end_datetime += timedelta(days=1)

        duration_minutes = int((end_datetime - start_datetime).total_seconds() / 60)
        total_duration += duration_minutes

        intervals.append({
            'id': row['id'],
            'event_date': row['event_date'],
            'start_time': row['start_time'],
            'end_time': row['end_time'],
            'note': row['note'],
            'activity_tag': row['activity_tag'],
            'duration_minutes': duration_minutes
        })

    # Create a color map for activity tags
    colors = ['#007bff', '#6610f2', '#6f42c1', '#e83e8c', '#dc3545', '#fd7e14', '#ffc107', '#28a745', '#20c997', '#17a2b8']
    tag_colors = {tag: colors[i % len(colors)] for i, tag in enumerate(activity_tags)}

    return render_template(
        'list_events.html',
        intervals=intervals,
        total_duration=total_duration,
        tag_colors=tag_colors,
        username=session['username'],
        role=session['role'],
        start_date=start_date,
        end_date=end_date
    )


@app.route('/edit_interval/<int:interval_id>', methods=['GET', 'POST'])
@login_required
def edit_interval(interval_id):
    """Handles editing of an existing interval."""
    db = get_db()
    # Fetch the interval and ensure it belongs to the current user
    user_id = get_user_id_from_session()
    interval = db.execute(
        'SELECT i.* FROM intervals i JOIN events e ON i.event_id = e.id WHERE i.id = ? AND e.user_id = ?',
        (interval_id, user_id)
    ).fetchone()

    if interval is None:
        flash('Interval not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('list_events'))

    if request.method == 'POST':
        start_time = request.form['start_time']
        end_time = request.form['end_time']
        note = request.form['note'].strip()
        activity_tag = request.form['activity_tag'].strip()

        if not start_time or not end_time or not activity_tag:
            flash('Start time, end time, and activity tag are required.', 'danger')
            return render_template('edit_interval.html', interval=interval, activity_tags=get_all_activity_tags(), username=session['username'], role=session['role'])

        if len(note) > 10:
            flash('Note must be max 10 characters.', 'danger')
            return render_template('edit_interval.html', interval=interval, activity_tags=get_all_activity_tags(), username=session['username'], role=session['role'])

        # Add tag to activity_tags table if new
        add_activity_tag_if_new(activity_tag)

        db.execute(
            'UPDATE intervals SET start_time = ?, end_time = ?, note = ?, activity_tag = ? WHERE id = ?',
            (start_time, end_time, note, activity_tag, interval_id)
        )
        db.commit()
        flash('Interval updated successfully!', 'success')
        return redirect(url_for('list_events'))

    # GET request
    activity_tags_list = get_all_activity_tags()
    return render_template('edit_interval.html', interval=interval, activity_tags=activity_tags_list, username=session['username'], role=session['role'])


if __name__ == '__main__':
    app.run(debug=True)