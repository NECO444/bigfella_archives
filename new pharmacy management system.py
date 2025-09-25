import sqlite3
from datetime import datetime, date
import tkinter as tk
from tkinter import messagebox, ttk
import shutil
import os
import re

class Medication:
    def __init__(self, name, quantity, price, expiration_date):
        self.name = name
        self.quantity = quantity
        self.price = price
        try:
            self.expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError("Expiration date must be in YYYY-MM-DD format")

    def is_expired(self):
        return self.expiration_date < date.today()

class Prescription:
    def __init__(self, patient_name, medication_name, dosage, doctor, date_issued):
        self.patient_name = patient_name
        self.medication_name = medication_name
        self.dosage = dosage
        self.doctor = doctor
        self.date_issued = date_issued

class PharmacyManagementSystem:
    def __init__(self, db_name="pharmacy.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_tables()
        self.create_indexes()
        self.setup_default_users()
        self.current_user = None
        self.current_role = None

    def create_tables(self):
        # Users table with plain-text passwords
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT CHECK(role IN ('admin', 'pharmacist'))
            )
        ''')
        # Medications table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS medications (
                name TEXT PRIMARY KEY,
                quantity INTEGER,
                price REAL,
                expiration_date TEXT
            )
        ''')
        # Prescriptions table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS prescriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_name TEXT,
                medication_name TEXT,
                dosage TEXT,
                doctor TEXT,
                date_issued TEXT,
                FOREIGN KEY (medication_name) REFERENCES medications (name)
            )
        ''')
        # Sales table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                medication_name TEXT,
                quantity INTEGER,
                total_price REAL,
                date_sold TEXT,
                patient_name TEXT,
                FOREIGN KEY (medication_name) REFERENCES medications (name)
            )
        ''')
        self.conn.commit()

    def create_indexes(self):
        # Indexes for performance
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_prescriptions_medication ON prescriptions (medication_name)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_sales_medication ON sales (medication_name)')
        self.conn.commit()

    def setup_default_users(self):
        # Add default admin and pharmacist users with plain-text passwords
        self.cursor.execute('SELECT COUNT(*) FROM users')
        if self.cursor.fetchone()[0] == 0:
            default_users = [
                ('admin', 'admin123', 'admin'),
                ('pharmacist', 'pharma123', 'pharmacist')
            ]
            for username, password, role in default_users:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO users (username, password, role)
                    VALUES (?, ?, ?)
                ''', (username, password, role))
            self.conn.commit()

    def backup_database(self):
        # Admin-only: Backup database
        if self.current_role != 'admin':
            return "Access denied: Admin role required."
        backup_file = f"{self.db_name}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            shutil.copyfile(self.db_name, backup_file)
            return f"Backup created: {backup_file}"
        except Exception as e:
            return f"Backup failed: {e}"

    def validate_input(self, name=None, quantity=None, price=None, expiration_date=None, patient_name=None, dosage=None, doctor=None, username=None, password=None):
        errors = []
        if name and not re.match(r'^[A-Za-z0-9\s-]+$', name):
            errors.append("Medication name must contain only letters, numbers, spaces, or hyphens.")
        if patient_name and not re.match(r'^[A-Za-z\s-]+$', patient_name):
            errors.append("Patient name must contain only letters, spaces, or hyphens.")
        if doctor and not re.match(r'^[A-Za-z\s.-]+$', doctor):
            errors.append("Doctor name must contain only letters, spaces, dots, or hyphens.")
        if username and not re.match(r'^[A-Za-z0-9_]+$', username):
            errors.append("Username must contain only letters, numbers, or underscores.")
        if password and len(password) < 6:
            errors.append("Password must be at least 6 characters long.")
        if quantity is not None:
            try:
                quantity = int(quantity)
                if quantity < 0:
                    errors.append("Quantity must be non-negative.")
            except ValueError:
                errors.append("Quantity must be a valid integer.")
        if price is not None:
            try:
                price = float(price)
                if price < 0:
                    errors.append("Price must be non-negative.")
            except ValueError:
                errors.append("Price must be a valid number.")
        if expiration_date:
            try:
                datetime.strptime(expiration_date, "%Y-%m-%d")
                if datetime.strptime(expiration_date, "%Y-%m-%d").date() < date.today():
                    errors.append("Expiration date cannot be in the past.")
            except ValueError:
                errors.append("Expiration date must be in YYYY-MM-DD format.")
        if dosage and not re.match(r'^[A-Za-z0-9\s,.()-]+$', dosage):
            errors.append("Dosage must contain only letters, numbers, spaces, or basic punctuation.")
        return errors

    def register_user(self, username, password, role):
        # Admin-only: Register new users
        if self.current_role != 'admin':
            return "Access denied: Admin role required."
        errors = self.validate_input(username=username, password=password)
        if errors:
            return "\n".join(errors)
        if role not in ['admin', 'pharmacist']:
            return "Invalid role. Must be 'admin' or 'pharmacist'."
        try:
            with self.conn:
                self.cursor.execute('''
                    INSERT INTO users (username, password, role)
                    VALUES (?, ?, ?)
                ''', (username, password, role))
            return f"User {username} registered successfully."
        except sqlite3.IntegrityError:
            return f"Username {username} already exists."

    def login(self, username, password):
        self.cursor.execute('SELECT password, role FROM users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        if not result:
            return "Invalid username or password."
        stored_password, role = result
        if password == stored_password:
            self.current_user = username
            self.current_role = role
            return f"Logged in as {username} ({role})."
        return "Invalid username or password."

    def remove_user(self, username):
        # Admin-only: Remove users
        if self.current_role != 'admin':
            return "Access denied: Admin role required."
        if username == self.current_user:
            return "Cannot remove the currently logged-in user."
        self.cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if not self.cursor.fetchone():
            return f"User {username} not found."
        with self.conn:
            self.cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        return f"User {username} removed successfully."

    def add_medication(self, name, quantity, price, expiration_date):
        # Both roles: Add medications
        if not self.current_user:
            return "Access denied: Please log in."
        errors = self.validate_input(name, quantity, price, expiration_date)
        if errors:
            return "\n".join(errors)
        try:
            with self.conn:
                self.cursor.execute('''
                    INSERT INTO medications (name, quantity, price, expiration_date)
                    VALUES (?, ?, ?, ?)
                ''', (name, int(quantity), float(price), expiration_date))
            return f"Added {name} to inventory."
        except sqlite3.IntegrityError:
            return f"Medication {name} already exists. Use update to modify."
        except Exception as e:
            return f"Error: {e}"

    def update_medication(self, name, quantity=None, price=None, expiration_date=None):
        # Admin-only for price updates, both roles for quantity/expiration
        if not self.current_user:
            return "Access denied: Please log in."
        if price is not None and self.current_role != 'admin':
            return "Access denied: Only admins can update medication prices."
        self.cursor.execute('SELECT * FROM medications WHERE name = ?', (name,))
        if not self.cursor.fetchone():
            return f"Medication {name} not found."
        errors = self.validate_input(name, quantity, price, expiration_date)
        if errors:
            return "\n".join(errors)
        updates = []
        values = []
        if quantity is not None:
            updates.append("quantity = ?")
            values.append(int(quantity))
        if price is not None:
            updates.append("price = ?")
            values.append(float(price))
        if expiration_date is not None:
            updates.append("expiration_date = ?")
            values.append(expiration_date)
        if updates:
            values.append(name)
            with self.conn:
                query = f"UPDATE medications SET {', '.join(updates)} WHERE name = ?"
                self.cursor.execute(query, values)
            return f"Updated {name} details."
        return "No updates provided."

    def view_inventory(self):
        # Both roles: View inventory
        if not self.current_user:
            return "Access denied: Please log in."
        self.cursor.execute('SELECT name, quantity, price, expiration_date FROM medications')
        medications = self.cursor.fetchall()
        if not medications:
            return "Inventory is empty."
        result = ["Inventory:"]
        for name, quantity, price, exp_date in medications:
            expiration_date = datetime.strptime(exp_date, "%Y-%m-%d").date()
            status = "Expired" if expiration_date < date.today() else "Valid"
            result.append(
                f"Name: {name}, Quantity: {quantity}, Price: K{price:.2f}, "
                f"Expiration: {expiration_date}, Status: {status}"
            )
        return "\n".join(result)

    def remove_expired_medications(self):
        # Admin-only: Remove expired medications
        if not self.current_user:
            return "Access denied: Please log in."
        if self.current_role != 'admin':
            return "Access denied: Admin role required."
        self.cursor.execute('SELECT name, expiration_date FROM medications')
        expired = []
        for name, exp_date in self.cursor.fetchall():
            if datetime.strptime(exp_date, "%Y-%m-%d").date() < date.today():
                expired.append(name)
        if expired:
            with self.conn:
                self.cursor.execute('DELETE FROM medications WHERE name IN ({})'.format(
                    ','.join('?' for _ in expired)), expired)
            return "\n".join(f"Removed expired medication: {name}" for name in expired)
        return "No expired medications found."

    def sell_medication(self, name, quantity, patient_name=None):
        # Both roles: Sell medications
        if not self.current_user:
            return "Access denied: Please log in."
        errors = self.validate_input(name, quantity, patient_name=patient_name)
        if errors:
            return "\n".join(errors)
        self.cursor.execute('SELECT name, quantity, price, expiration_date FROM medications WHERE name = ?', (name,))
        result = self.cursor.fetchone()
        if not result:
            return f"Medication {name} not found."
        _, current_quantity, price, exp_date = result
        expiration_date = datetime.strptime(exp_date, "%Y-%m-%d").date()
        if expiration_date < date.today():
            return f"Cannot sell {name}: Medication is expired."
        if current_quantity < int(quantity):
            return f"Insufficient stock for {name}. Available: {current_quantity}"
        total_price = float(price) * int(quantity)
        new_quantity = current_quantity - int(quantity)
        with self.conn:
            if new_quantity == 0:
                self.cursor.execute('DELETE FROM medications WHERE name = ?', (name,))
            else:
                self.cursor.execute('UPDATE medications SET quantity = ? WHERE name = ?', (new_quantity, name))
            self.cursor.execute('''
                INSERT INTO sales (medication_name, quantity, total_price, date_sold, patient_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, int(quantity), total_price, date.today().strftime("%Y-%m-%d"), patient_name))
        result = [f"Sold {quantity} units of {name}. Total: K{total_price:.2f}"]
        if patient_name:
            result.append(f"Receipt for {patient_name}: {quantity} x {name} @ K{price:.2f} = K{total_price:.2f}")
        if new_quantity == 0:
            result.append(f"{name} is out of stock and removed from inventory.")
        return "\n".join(result)

    def add_prescription(self, patient_name, medication_name, dosage, doctor):
        # Both roles: Add prescriptions
        if not self.current_user:
            return "Access denied: Please log in."
        errors = self.validate_input(medication_name, patient_name=patient_name, dosage=dosage, doctor=doctor)
        if errors:
            return "\n".join(errors)
        self.cursor.execute('SELECT name FROM medications WHERE name = ?', (medication_name,))
        if not self.cursor.fetchone():
            return f"Medication {medication_name} not in inventory."
        with self.conn:
            self.cursor.execute('''
                INSERT INTO prescriptions (patient_name, medication_name, dosage, doctor, date_issued)
                VALUES (?, ?, ?, ?, ?)
            ''', (patient_name, medication_name, dosage, doctor, date.today().strftime("%Y-%m-%d")))
        return f"Prescription added for {patient_name}."

    def view_prescriptions(self):
        # Both roles: View prescriptions
        if not self.current_user:
            return "Access denied: Please log in."
        self.cursor.execute('SELECT patient_name, medication_name, dosage, doctor, date_issued FROM prescriptions')
        prescriptions = self.cursor.fetchall()
        if not prescriptions:
            return "No prescriptions recorded."
        result = ["Prescription History:"]
        for patient_name, med_name, dosage, doctor, date_issued in prescriptions:
            result.append(
                f"Patient: {patient_name}, Medication: {med_name}, Dosage: {dosage}, "
                f"Doctor: {doctor}, Issued: {date_issued}"
            )
        return "\n".join(result)

    def generate_sales_report(self):
        # Admin-only: Generate sales report
        if self.current_role != 'admin':
            return "Access denied: Admin role required."
        self.cursor.execute('SELECT id, medication_name, quantity, total_price, date_sold, patient_name FROM sales')
        sales = self.cursor.fetchall()
        if not sales:
            return "No sales recorded."
        result = ["Sales Report:"]
        total_revenue = 0
        for id, med_name, qty, total_price, date_sold, patient in sales:
            result.append(f"ID: {id}, Medication: {med_name}, Quantity: {qty}, Total: K{total_price:.2f}, Date: {date_sold}, Patient: {patient or 'N/A'}")
            total_revenue += total_price
        result.append(f"Total Revenue: K{total_revenue:.2f}")
        return "\n".join(result)

    def generate_inventory_report(self):
        # Admin-only: Generate inventory report
        if self.current_role != 'admin':
            return "Access denied: Admin role required."
        self.cursor.execute('SELECT name, quantity, price FROM medications')
        meds = self.cursor.fetchall()
        if not meds:
            return "Inventory is empty."
        result = ["Inventory Report:"]
        total_value = 0
        total_quantity = 0
        for name, qty, price in meds:
            value = qty * price
            result.append(f"Name: {name}, Quantity: {qty}, Price: K{price:.2f}, Value: K{value:.2f}")
            total_value += value
            total_quantity += qty
        result.append(f"Total Items: {total_quantity}, Total Value: K{total_value:.2f}")
        return "\n".join(result)

    def __del__(self):
        self.conn.close()

class PharmacyGUI:
    def __init__(self, root):
        self.pharmacy = PharmacyManagementSystem()
        self.root = root
        self.root.title("Pharmacy Management System")
        self.root.geometry("800x600")
        self.show_login_screen()

    def display_output(self, message):
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, message)
        self.output_text.config(state='disabled')

    def show_login_screen(self):
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Login")
        self.login_window.geometry("300x150")

        ttk.Label(self.login_window, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.login_window)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.login_window, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.login_window, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(self.login_window, text="Login", command=self.handle_login).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(self.login_window, text="Register", command=self.show_register_screen).grid(row=3, column=0, columnspan=2, pady=5)

        # Disable main window until login
        self.root.withdraw()

    def show_register_screen(self):
        if self.pharmacy.current_role != 'admin':
            messagebox.showerror("Access Denied", "Only admins can register new users.")
            return
        register_window = tk.Toplevel(self.root)
        register_window.title("Register")
        register_window.geometry("300x200")

        ttk.Label(register_window, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        username_entry = ttk.Entry(register_window)
        username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(register_window, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        password_entry = ttk.Entry(register_window, show="*")
        password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(register_window, text="Role (admin/pharmacist):").grid(row=2, column=0, padx=5, pady=5)
        role_entry = ttk.Entry(register_window)
        role_entry.grid(row=2, column=1, padx=5, pady=5)

        def submit():
            result = self.pharmacy.register_user(username_entry.get(), password_entry.get(), role_entry.get())
            messagebox.showinfo("Register", result)
            if "successfully" in result:
                register_window.destroy()

        ttk.Button(register_window, text="Submit", command=submit).grid(row=3, column=0, columnspan=2, pady=10)

    def handle_login(self):
        result = self.pharmacy.login(self.username_entry.get(), self.password_entry.get())
        if "Logged in" in result:
            self.login_window.destroy()
            self.root.deiconify()
            self.show_main_screen()
        else:
            messagebox.showerror("Login Failed", result)

    def show_main_screen(self):
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Display logged-in user and role
        ttk.Label(self.main_frame, text=f"Logged in as: {self.pharmacy.current_user} ({self.pharmacy.current_role})").grid(row=0, column=0, columnspan=2, pady=5)

        # Buttons for actions (role-based visibility)
        row = 1
        ttk.Button(self.main_frame, text="Add Medication", command=self.add_medication).grid(row=row, column=0, pady=5)
        row += 1
        if self.pharmacy.current_role == 'admin':
            ttk.Button(self.main_frame, text="Update Medication", command=self.update_medication).grid(row=row, column=0, pady=5)
            row += 1
        else:
            ttk.Button(self.main_frame, text="Update Medication (Quantity/Expiration)", command=self.update_medication_limited).grid(row=row, column=0, pady=5)
            row += 1
        ttk.Button(self.main_frame, text="View Inventory", command=self.view_inventory).grid(row=row, column=0, pady=5)
        row += 1
        if self.pharmacy.current_role == 'admin':
            ttk.Button(self.main_frame, text="Remove Expired Medications", command=self.remove_expired).grid(row=row, column=0, pady=5)
            row += 1
        ttk.Button(self.main_frame, text="Sell Medication", command=self.sell_medication).grid(row=row, column=0, pady=5)
        row += 1
        ttk.Button(self.main_frame, text="Add Prescription", command=self.add_prescription).grid(row=row, column=0, pady=5)
        row += 1
        ttk.Button(self.main_frame, text="View Prescriptions", command=self.view_prescriptions).grid(row=row, column=0, pady=5)
        row += 1
        if self.pharmacy.current_role == 'admin':
            ttk.Button(self.main_frame, text="Generate Sales Report", command=self.generate_sales_report).grid(row=row, column=0, pady=5)
            row += 1
            ttk.Button(self.main_frame, text="Generate Inventory Report", command=self.generate_inventory_report).grid(row=row, column=0, pady=5)
            row += 1
            ttk.Button(self.main_frame, text="Backup Database", command=self.backup_database).grid(row=row, column=0, pady=5)
            row += 1
            ttk.Button(self.main_frame, text="Manage Users", command=self.manage_users).grid(row=row, column=0, pady=5)
            row += 1
        ttk.Button(self.main_frame, text="Logout", command=self.logout).grid(row=row, column=0, pady=5)

        # Output area
        self.output_text = tk.Text(self.main_frame, height=20, width=60)
        self.output_text.grid(row=1, column=1, rowspan=row, padx=10)
        self.output_text.config(state='disabled')

    def logout(self):
        self.pharmacy.current_user = None
        self.pharmacy.current_role = None
        self.main_frame.destroy()
        self.root.withdraw()
        self.show_login_screen()

    def manage_users(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Manage Users")
        dialog.geometry("300x150")

        ttk.Label(dialog, text="Username to Remove:").grid(row=0, column=0, padx=5, pady=5)
        username_entry = ttk.Entry(dialog)
        username_entry.grid(row=0, column=1, padx=5, pady=5)

        def remove():
            result = self.pharmacy.remove_user(username_entry.get())
            self.display_output(result)
            dialog.destroy()

        ttk.Button(dialog, text="Remove User", command=remove).grid(row=1, column=0, columnspan=2, pady=10)

    def add_medication(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Medication")
        dialog.geometry("300x200")

        ttk.Label(dialog, text="Name:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Quantity:").grid(row=1, column=0, padx=5, pady=5)
        quantity_entry = ttk.Entry(dialog)
        quantity_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Price:").grid(row=2, column=0, padx=5, pady=5)
        price_entry = ttk.Entry(dialog)
        price_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Expiration (YYYY-MM-DD):").grid(row=3, column=0, padx=5, pady=5)
        exp_entry = ttk.Entry(dialog)
        exp_entry.grid(row=3, column=1, padx=5, pady=5)

        def submit():
            result = self.pharmacy.add_medication(
                name_entry.get(), quantity_entry.get(), price_entry.get(), exp_entry.get()
            )
            self.display_output(result)
            dialog.destroy()

        ttk.Button(dialog, text="Submit", command=submit).grid(row=4, column=0, columnspan=2, pady=10)

    def update_medication(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Update Medication")
        dialog.geometry("300x200")

        ttk.Label(dialog, text="Name:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Quantity (optional):").grid(row=1, column=0, padx=5, pady=5)
        quantity_entry = ttk.Entry(dialog)
        quantity_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Price (optional):").grid(row=2, column=0, padx=5, pady=5)
        price_entry = ttk.Entry(dialog)
        price_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Expiration (YYYY-MM-DD, optional):").grid(row=3, column=0, padx=5, pady=5)
        exp_entry = ttk.Entry(dialog)
        exp_entry.grid(row=3, column=1, padx=5, pady=5)

        def submit():
            result = self.pharmacy.update_medication(
                name_entry.get(), quantity_entry.get(), price_entry.get(), exp_entry.get()
            )
            self.display_output(result)
            dialog.destroy()

        ttk.Button(dialog, text="Submit", command=submit).grid(row=4, column=0, columnspan=2, pady=10)

    def update_medication_limited(self):
        # Limited update for pharmacists (no price updates)
        dialog = tk.Toplevel(self.root)
        dialog.title("Update Medication (Quantity/Expiration)")
        dialog.geometry("300x150")

        ttk.Label(dialog, text="Name:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Quantity (optional):").grid(row=1, column=0, padx=5, pady=5)
        quantity_entry = ttk.Entry(dialog)
        quantity_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Expiration (YYYY-MM-DD, optional):").grid(row=2, column=0, padx=5, pady=5)
        exp_entry = ttk.Entry(dialog)
        exp_entry.grid(row=2, column=1, padx=5, pady=5)

        def submit():
            result = self.pharmacy.update_medication(
                name_entry.get(), quantity_entry.get(), None, exp_entry.get()
            )
            self.display_output(result)
            dialog.destroy()

        ttk.Button(dialog, text="Submit", command=submit).grid(row=3, column=0, columnspan=2, pady=10)

    def view_inventory(self):
        self.display_output(self.pharmacy.view_inventory())

    def remove_expired(self):
        self.display_output(self.pharmacy.remove_expired_medications())

    def sell_medication(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Sell Medication")
        dialog.geometry("300x150")

        ttk.Label(dialog, text="Medication Name:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Quantity:").grid(row=1, column=0, padx=5, pady=5)
        quantity_entry = ttk.Entry(dialog)
        quantity_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Patient Name (optional):").grid(row=2, column=0, padx=5, pady=5)
        patient_entry = ttk.Entry(dialog)
        patient_entry.grid(row=2, column=1, padx=5, pady=5)

        def submit():
            result = self.pharmacy.sell_medication(name_entry.get(), quantity_entry.get(), patient_entry.get())
            self.display_output(result)
            dialog.destroy()

        ttk.Button(dialog, text="Submit", command=submit).grid(row=3, column=0, columnspan=2, pady=10)

    def add_prescription(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Prescription")
        dialog.geometry("300x200")

        ttk.Label(dialog, text="Patient Name:").grid(row=0, column=0, padx=5, pady=5)
        patient_entry = ttk.Entry(dialog)
        patient_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Medication Name:").grid(row=1, column=0, padx=5, pady=5)
        med_entry = ttk.Entry(dialog)
        med_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Dosage:").grid(row=2, column=0, padx=5, pady=5)
        dosage_entry = ttk.Entry(dialog)
        dosage_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Doctor:").grid(row=3, column=0, padx=5, pady=5)
        doctor_entry = ttk.Entry(dialog)
        doctor_entry.grid(row=3, column=1, padx=5, pady=5)

        def submit():
            result = self.pharmacy.add_prescription(
                patient_entry.get(), med_entry.get(), dosage_entry.get(), doctor_entry.get()
            )
            self.display_output(result)
            dialog.destroy()

        ttk.Button(dialog, text="Submit", command=submit).grid(row=4, column=0, columnspan=2, pady=10)

    def view_prescriptions(self):
        self.display_output(self.pharmacy.view_prescriptions())

    def generate_sales_report(self):
        self.display_output(self.pharmacy.generate_sales_report())

    def generate_inventory_report(self):
        self.display_output(self.pharmacy.generate_inventory_report())

    def backup_database(self):
        self.display_output(self.pharmacy.backup_database())

def main():
    root = tk.Tk()
    app = PharmacyGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()