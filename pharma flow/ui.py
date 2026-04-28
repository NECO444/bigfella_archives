# ui.py
# Console-based User Interface with Expiry Date Alerts

from models import *
from datetime import datetime

def print_header():
    print("="*70)
    print("          PHARMAFLOW MWK - Pharmacy Management System")
    print("                   Prices in Malawi Kwacha (MWK)")
    print("="*70)

def show_expiry_alert():
    """Display strong expiry warnings"""
    expiring = get_expiring_drugs()
    if not expiring:
        print("✅ No expiry alerts at the moment.\n")
        return
    
    print("⚠️  EXPIRY ALERTS".center(70))
    print("-"*70)
    print(f"{'Drug Name':<35} {'Stock':<8} {'Expiry':<12} {'Status':<15}")
    print("-"*70)
    
    for drug in expiring:
        status = drug.get_expiry_status()
        color = "\033[91m" if status["status"] == "expired" else "\033[93m"
        reset = "\033[0m"
        print(f"{color}{drug.name:<35} {drug.stock:<8} {drug.expiry_date:<12} {status['text']:<15}{reset}")
    print("-"*70)
    print(f"Total drugs needing attention: {len(expiring)}\n")

def show_inventory():
    """Display full inventory with expiry status"""
    drugs = get_all_drugs()
    print(f"{'ID':<4} {'Drug Name':<35} {'Stock':<8} {'Price(MWK)':<12} {'Expiry':<12} {'Status'}")
    print("-"*85)
    
    for drug in drugs:
        status = drug.get_expiry_status()
        color = "\033[91m" if status["status"] == "expired" else "\033[93m" if status["status"] == "soon" else "\033[92m"
        reset = "\033[0m"
        print(f"{drug.id:<4} {drug.name:<35} {drug.stock:<8} {drug.price:,.0f} MWK    {drug.expiry_date:<12} {color}{status['text']}{reset}")
    print()

def main_menu():
    print_header()
    show_expiry_alert()   # Always show expiry alert on startup
    
    while True:
        print("\nMAIN MENU")
        print("1. Dashboard (with Expiry Alerts)")
        print("2. View Full Inventory")
        print("3. Add New Drug")
        print("4. Update Stock")
        print("5. Record Sale")
        print("6. Record Prescription")
        print("7. Exit")
        
        choice = input("\nEnter your choice (1-7): ").strip()
        
        if choice == "1":
            show_expiry_alert()
        elif choice == "2":
            show_inventory()
        elif choice == "3":
            name = input("Drug Name: ")
            stock = int(input("Initial Stock: "))
            price = float(input("Price (MWK): "))
            expiry = input("Expiry Date (YYYY-MM-DD): ")
            add_drug(name, stock, price, expiry)
            print("✅ Drug added successfully!")
        elif choice == "4":
            show_inventory()
            drug_id = int(input("\nEnter Drug ID to update: "))
            new_stock = int(input("New Stock Quantity: "))
            update_stock(drug_id, new_stock)
            print("✅ Stock updated!")
        elif choice == "5":
            show_inventory()
            drug_id = int(input("\nEnter Drug ID to sell: "))
            qty = int(input("Quantity to sell: "))
            # Get drug details
            drugs = get_all_drugs()
            drug = next((d for d in drugs if d.id == drug_id), None)
            if not drug:
                print("❌ Drug not found!")
                continue
            if drug.stock < qty:
                print(f"❌ Insufficient stock! Available: {drug.stock}")
                continue
            items = [{'drug_id': drug_id, 'qty': qty, 'price': drug.price}]
            total = record_sale("cashier", items)
            print(f"✅ Sale recorded! Total: {total:,.0f} MWK")
        elif choice == "6":
            patient_name = input("Patient Name: ")
            patient_phone = input("Patient Phone: ")
            show_inventory()
            drug_id = int(input("Drug ID: "))
            quantity = int(input("Quantity: "))
            notes = input("Notes: ")
            prescribed_by = input("Prescribed by: ")
            record_prescription(patient_name, patient_phone, drug_id, quantity, notes, prescribed_by)
            print("✅ Prescription recorded!")
        elif choice == "7":
            print("Thank you for using PharmaFlow MWK!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    from database import init_database
    init_database()
    main_menu()