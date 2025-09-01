import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Drop existing tables if they exist
    cursor.execute("DROP TABLE IF EXISTS events;")
    cursor.execute("DROP TABLE IF EXISTS intervals;")
    cursor.execute("DROP TABLE IF EXISTS activity_tags;")
    cursor.execute("DROP TABLE IF EXISTS users;")

    # Create users table
    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'standard')),
        must_change_password INTEGER NOT NULL DEFAULT 0
    );
    """)

    # Create events table
    cursor.execute("""
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        event_date TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)

    # Create intervals table
    cursor.execute("""
    CREATE TABLE intervals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        note TEXT,
        activity_tag TEXT NOT NULL,
        FOREIGN KEY (event_id) REFERENCES events (id)
    );
    """)

    # Create activity_tags table
    cursor.execute("""
    CREATE TABLE activity_tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tag_name TEXT UNIQUE NOT NULL
    );
    """)


    # Insert a default admin user
    admin_username = "admin"
    admin_password = "password"
    hashed_password = generate_password_hash(admin_password)
    cursor.execute(
        "INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, ?)",
        (admin_username, hashed_password, 'admin', 0)
    )

    conn.commit()
    conn.close()
    print("Database initialized with the original schema.")
    print(f"Default admin user created with username: {admin_username} and password: {admin_password}")

if __name__ == '__main__':
    init_db()