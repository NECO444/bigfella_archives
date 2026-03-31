import hashlib

# Security Note: Updated password handling and storage mechanisms.
# The following improvements have been made to enhance security:
# 1. Passwords are now hashed using hashlib instead of being stored in plain-text.
# 2. The password column name has been updated from 'password_hash' to 'password' to match the schema.
# 3. The login method now verifies hashed passwords.
# 4. Register_user hashes passwords before storage.
# 5. Setup_default_users hashes default passwords.

class PharmacyManagementSystem:

    def __init__(self):
        self.users = { }

    def hash_password(self, password):
        # Generates a hashed password.
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password):
        hashed_password = self.hash_password(password)
        # Store user with the hashed password
        self.users[username] = {'password': hashed_password}

    def login(self, username, password):
        hashed_password = self.hash_password(password)
        return self.users.get(username, {}).get('password') == hashed_password

    def setup_default_users(self):
        # Hashes default passwords for predefined users.
        self.register_user('admin', self.hash_password('adminpass'))
        self.register_user('user', self.hash_password('userpass'))
