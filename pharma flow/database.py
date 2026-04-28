# database.py
# Handles all SQLite database operations

import sqlite3
from datetime import datetime

DB_NAME = "pharmacy_mwk.db"

def get_connection():
    """Create and return database connection"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

def init_database():
    """Create all tables if they don't exist"""
    conn = get_connection()
    cursor = conn.cursor()

    # Drugs table with expiry date
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS drugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        stock INTEGER DEFAULT 0,
        price REAL NOT NULL,
        expiry_date TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Sales table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sale_date TEXT DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        total_amount REAL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    # Sale Items (for detailed sales)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sale_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sale_id INTEGER,
        drug_id INTEGER,
        quantity INTEGER,
        price_per_unit REAL,
        FOREIGN KEY(sale_id) REFERENCES sales(id),
        FOREIGN KEY(drug_id) REFERENCES drugs(id)
    )
    ''')

    # Prescriptions for recurring patients
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS prescriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_name TEXT,
        patient_phone TEXT,
        drug_id INTEGER,
        quantity INTEGER,
        notes TEXT,
        prescribed_date TEXT DEFAULT CURRENT_TIMESTAMP,
        prescribed_by TEXT,
        FOREIGN KEY(drug_id) REFERENCES drugs(id)
    )
    ''')

    # Users (Manager, Pharmacist, Cashier)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('manager', 'pharmacist', 'cashier'))
    )
    ''')

    # Insert default users if none exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_users = [
            ("manager", "password123", "manager"),
            ("pharmacist", "password123", "pharmacist"),
            ("cashier", "password123", "cashier")
        ]
        cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", default_users)

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully with expiry tracking.")

# Call this when starting the app
if __name__ == "__main__":
    init_database()