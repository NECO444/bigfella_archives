# main.py
# Main entry point for the Pharmacy Management System

from database import init_database
from ui import main_menu

if __name__ == "__main__":
    print("🚀 Starting PharmaFlow MWK Pharmacy System...")
    init_database()
    main_menu()