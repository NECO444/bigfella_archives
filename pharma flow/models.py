# models.py
# Core business logic including expiry date alerts

from database import get_connection
from datetime import datetime, timedelta

class Drug:
    def __init__(self, id, name, stock, price, expiry_date):
        self.id = id
        self.name = name
        self.stock = stock
        self.price = price
        self.expiry_date = expiry_date

    def get_expiry_status(self):
        """Return expiry status: 'expired', 'soon', or 'good'"""
        try:
            expiry = datetime.strptime(self.expiry_date, "%Y-%m-%d")
            today = datetime.now().date()
            days_left = (expiry.date() - today).days

            if days_left < 0:
                return {"status": "expired", "text": "EXPIRED", "color": "red", "days": days_left}
            elif days_left <= 30:
                return {"status": "soon", "text": f"{days_left} days left", "color": "orange", "days": days_left}
            else:
                return {"status": "good", "text": "Good", "color": "green", "days": days_left}
        except:
            return {"status": "unknown", "text": "Invalid Date", "color": "gray", "days": 0}


def add_drug(name, stock, price, expiry_date):
    """Add new drug with expiry date"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO drugs (name, stock, price, expiry_date)
        VALUES (?, ?, ?, ?)
    """, (name, stock, price, expiry_date))
    conn.commit()
    conn.close()


def get_all_drugs():
    """Return all drugs"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM drugs ORDER BY name")
    rows = cursor.fetchall()
    conn.close()
    return [Drug(row['id'], row['name'], row['stock'], row['price'], row['expiry_date']) for row in rows]


def get_expiring_drugs():
    """Return drugs that are expired or expiring within 30 days"""
    today = datetime.now().strftime("%Y-%m-%d")
    conn = get_connection()
    cursor = conn.cursor()
    
    # Expiry within 30 days or already expired
    cursor.execute("""
        SELECT * FROM drugs 
        WHERE expiry_date <= date(?, '+30 days')
        ORDER BY expiry_date
    """, (today,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [Drug(row['id'], row['name'], row['stock'], row['price'], row['expiry_date']) for row in rows]


def update_stock(drug_id, new_stock):
    """Update drug stock quantity"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE drugs SET stock = ? WHERE id = ?", (new_stock, drug_id))
    conn.commit()
    conn.close()


def record_sale(user_role, items):
    """Record a sale and reduce stock"""
    conn = get_connection()
    cursor = conn.cursor()
    
    total = sum(item['price'] * item['qty'] for item in items)
    
    # Create sale record
    cursor.execute("INSERT INTO sales (user_id, total_amount) VALUES (?, ?)", 
                  (1, total))  # Simplified - use real user_id later
    sale_id = cursor.lastrowid
    
    # Record each item and reduce stock
    for item in items:
        cursor.execute("""
            INSERT INTO sale_items (sale_id, drug_id, quantity, price_per_unit)
            VALUES (?, ?, ?, ?)
        """, (sale_id, item['drug_id'], item['qty'], item['price']))
        
        # Reduce stock
        cursor.execute("UPDATE drugs SET stock = stock - ? WHERE id = ?", 
                      (item['qty'], item['drug_id']))
    
    conn.commit()
    conn.close()
    return total


def record_prescription(patient_name, patient_phone, drug_id, quantity, notes, prescribed_by):
    """Record a prescription"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO prescriptions (patient_name, patient_phone, drug_id, quantity, notes, prescribed_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (patient_name, patient_phone, drug_id, quantity, notes, prescribed_by))
    conn.commit()
    conn.close()