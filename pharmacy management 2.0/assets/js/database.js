// Pharmacy Management System - Local Database Management
// Using localStorage for data persistence

class PharmacyDatabase {
  constructor() {
    this.initializeDatabase();
  }

  // Initialize database with default data if empty
  initializeDatabase() {
    // Initialize roles
    if (!localStorage.getItem('pharmacy_roles')) {
      const defaultRoles = [
        { id: 1, name: 'Admin', description: 'Full system access', permissions: ['view_all', 'edit_all', 'delete_all', 'manage_users', 'manage_roles', 'view_reports', 'export_data'] },
        { id: 2, name: 'Pharmacist', description: 'Manage medicines and sales', permissions: ['view_inventory', 'edit_inventory', 'view_sales', 'create_sales', 'view_reports'] },
        { id: 3, name: 'Cashier', description: 'Handle sales and payments', permissions: ['view_inventory', 'view_sales', 'create_sales'] },
        { id: 4, name: 'Manager', description: 'View and manage reports', permissions: ['view_all', 'view_reports', 'export_data'] }
      ];
      localStorage.setItem('pharmacy_roles', JSON.stringify(defaultRoles));
    }

    // Initialize users
    if (!localStorage.getItem('pharmacy_users')) {
      const defaultUsers = [
        { id: 1, username: 'admin', password: this.hashPassword('admin123'), fullName: 'Administrator', email: 'admin@pharmacy.com', roleId: 1, status: 'active', createdAt: new Date().toISOString() },
        { id: 2, username: 'pharmacist', password: this.hashPassword('pharm123'), fullName: 'John Doe', email: 'john@pharmacy.com', roleId: 2, status: 'active', createdAt: new Date().toISOString() },
        { id: 3, username: 'cashier', password: this.hashPassword('cash123'), fullName: 'Jane Smith', email: 'jane@pharmacy.com', roleId: 3, status: 'active', createdAt: new Date().toISOString() }
      ];
      localStorage.setItem('pharmacy_users', JSON.stringify(defaultUsers));
    }

    if (!localStorage.getItem('pharmacy_medicines')) {
      const defaultMedicines = [
        { id: 1, name: 'Aspirin 500mg', batch: 'ASP-2026-001', quantity: 250, price: 2.50, expiryDate: '2027-12-31', manufacturer: 'PharmaCorp', description: 'Pain relief' },
        { id: 2, name: 'Vitamin D3 1000IU', batch: 'VIT-2026-045', quantity: 45, price: 5.20, expiryDate: '2027-06-15', manufacturer: 'VitaHealth', description: 'Vitamin supplement' },
        { id: 3, name: 'Amoxicillin 250mg', batch: 'AMX-2026-012', quantity: 8, price: 3.75, expiryDate: '2027-05-20', manufacturer: 'MedLabs', description: 'Antibiotic' },
        { id: 4, name: 'Ibuprofen 200mg', batch: 'IBU-2026-089', quantity: 320, price: 1.80, expiryDate: '2026-12-10', manufacturer: 'PharmaCorp', description: 'Anti-inflammatory' },
        { id: 5, name: 'Paracetamol 500mg', batch: 'PAR-2026-034', quantity: 150, price: 1.50, expiryDate: '2027-11-30', manufacturer: 'MedLabs', description: 'Pain relief' },
        { id: 6, name: 'Metformin 500mg', batch: 'MET-2026-056', quantity: 180, price: 4.20, expiryDate: '2027-08-25', manufacturer: 'DiabetesCare', description: 'Diabetes medication' }
      ];
      localStorage.setItem('pharmacy_medicines', JSON.stringify(defaultMedicines));
    }

    if (!localStorage.getItem('pharmacy_transactions')) {
      const defaultTransactions = [
        { id: 1, date: new Date('2026-04-27').toISOString(), customer: 'Ahmed Khan', phone: '+265 999 123 456', medicines: [{ name: 'Aspirin 500mg', quantity: 2, price: 2.50 }], subtotal: 5.00, tax: 0.50, total: 5.50, paymentMethod: 'Cash' },
        { id: 2, date: new Date('2026-04-27').toISOString(), customer: 'Fatima Ali', phone: '+265 999 654 321', medicines: [{ name: 'Vitamin D3 1000IU', quantity: 1, price: 5.20 }], subtotal: 5.20, tax: 0.52, total: 5.72, paymentMethod: 'Card' },
        { id: 3, date: new Date('2026-04-26').toISOString(), customer: 'Muhammad Hassan', phone: '+265 999 456 789', medicines: [{ name: 'Amoxicillin 250mg', quantity: 3, price: 3.75 }], subtotal: 11.25, tax: 1.13, total: 12.38, paymentMethod: 'Cash' }
      ];
      localStorage.setItem('pharmacy_transactions', JSON.stringify(defaultTransactions));
    }

    if (!localStorage.getItem('pharmacy_customers')) {
      const defaultCustomers = [
        { id: 1, name: 'Ahmed Khan', phone: '+265 999 123 456', email: 'ahmed@email.com', visits: 5, totalSpent: 25.50, lastVisit: '2026-04-27' },
        { id: 2, name: 'Fatima Ali', phone: '+265 999 654 321', email: 'fatima@email.com', visits: 3, totalSpent: 15.75, lastVisit: '2026-04-27' },
        { id: 3, name: 'Muhammad Hassan', phone: '+265 999 456 789', email: 'hassan@email.com', visits: 8, totalSpent: 45.00, lastVisit: '2026-04-26' },
        { id: 4, name: 'Aisha Ibrahim', phone: '+265 999 987 654', email: 'aisha@email.com', visits: 2, totalSpent: 8.00, lastVisit: '2026-04-26' }
      ];
      localStorage.setItem('pharmacy_customers', JSON.stringify(defaultCustomers));
    }

    if (!localStorage.getItem('pharmacy_prescriptions')) {
      const defaultPrescriptions = [
        { id: 1, customerId: 1, customerName: 'Ahmed Khan', doctorName: 'Dr. Amina Khan', date: '2026-04-25', expiryDate: '2026-07-25', medicines: [{ name: 'Aspirin 500mg', dosage: '1 tablet', frequency: 'Twice daily', duration: '7 days' }], notes: 'For headache relief', status: 'active' }
      ];
      localStorage.setItem('pharmacy_prescriptions', JSON.stringify(defaultPrescriptions));
    }

    if (!localStorage.getItem('pharmacy_items')) {
      const defaultItems = [
        { id: 1, name: 'Sterile Bandages (Pack of 20)', category: 'First Aid', quantity: 150, price: 2.50, supplier: 'MediSupply Co', description: 'Sterile adhesive bandages', expiryDate: '2027-12-31' },
        { id: 2, name: 'Antiseptic Wipes', category: 'First Aid', quantity: 80, price: 3.00, supplier: 'MediSupply Co', description: 'Alcohol-based antiseptic wipes', expiryDate: '2027-06-30' },
        { id: 3, name: 'Thermometer (Digital)', category: 'Medical Equipment', quantity: 25, price: 8.50, supplier: 'TechMed', description: 'Digital thermometer', expiryDate: '' },
        { id: 4, name: 'Cough Drops (Mint)', category: 'OTC Products', quantity: 200, price: 1.50, supplier: 'SweetHealth', description: 'Mentholated cough drops', expiryDate: '2026-08-15' },
        { id: 5, name: 'Elastic Bandage 2 inch', category: 'First Aid', quantity: 120, price: 4.00, supplier: 'MediSupply Co', description: 'Elastic compression bandage', expiryDate: '2027-10-20' },
        { id: 6, name: 'Hand Sanitizer 500ml', category: 'Hygiene', quantity: 60, price: 5.50, supplier: 'CleanCare', description: 'Alcohol-based hand sanitizer', expiryDate: '2026-09-15' }
      ];
      localStorage.setItem('pharmacy_items', JSON.stringify(defaultItems));
    }
  }

  // ============= MEDICINES MANAGEMENT =============
  getMedicines() {
    return JSON.parse(localStorage.getItem('pharmacy_medicines')) || [];
  }

  getMedicineById(id) {
    const medicines = this.getMedicines();
    return medicines.find(m => m.id === id);
  }

  addMedicine(medicine) {
    const medicines = this.getMedicines();
    const newMedicine = {
      id: Math.max(...medicines.map(m => m.id), 0) + 1,
      ...medicine,
      quantity: parseInt(medicine.quantity),
      price: parseFloat(medicine.price)
    };
    medicines.push(newMedicine);
    localStorage.setItem('pharmacy_medicines', JSON.stringify(medicines));
    return newMedicine;
  }

  updateMedicine(id, updates) {
    const medicines = this.getMedicines();
    const index = medicines.findIndex(m => m.id === id);
    if (index !== -1) {
      medicines[index] = { ...medicines[index], ...updates };
      localStorage.setItem('pharmacy_medicines', JSON.stringify(medicines));
      return medicines[index];
    }
    return null;
  }

  deleteMedicine(id) {
    const medicines = this.getMedicines().filter(m => m.id !== id);
    localStorage.setItem('pharmacy_medicines', JSON.stringify(medicines));
    return true;
  }

  updateMedicineQuantity(medicineName, quantityChange) {
    const medicines = this.getMedicines();
    const medicine = medicines.find(m => m.name === medicineName);
    if (medicine) {
      medicine.quantity += quantityChange;
      if (medicine.quantity < 0) medicine.quantity = 0;
      localStorage.setItem('pharmacy_medicines', JSON.stringify(medicines));
      return medicine;
    }
    return null;
  }

  // ============= TRANSACTIONS MANAGEMENT =============
  getTransactions() {
    return JSON.parse(localStorage.getItem('pharmacy_transactions')) || [];
  }

  addTransaction(transaction) {
    const transactions = this.getTransactions();
    const newTransaction = {
      id: Math.max(...transactions.map(t => t.id), 0) + 1,
      date: new Date().toISOString(),
      ...transaction
    };
    transactions.push(newTransaction);
    localStorage.setItem('pharmacy_transactions', JSON.stringify(transactions));
    
    // Update customer info
    this.updateOrCreateCustomer(transaction.customer, transaction.phone, transaction.total);
    
    return newTransaction;
  }

  getRecentTransactions(limit = 5) {
    const transactions = this.getTransactions();
    return transactions.sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, limit);
  }

  // ============= CUSTOMERS MANAGEMENT =============
  getCustomers() {
    return JSON.parse(localStorage.getItem('pharmacy_customers')) || [];
  }

  getCustomerById(id) {
    const customers = this.getCustomers();
    return customers.find(c => c.id === id);
  }

  addCustomer(customer) {
    const customers = this.getCustomers();
    const newCustomer = {
      id: Math.max(...customers.map(c => c.id), 0) + 1,
      visits: 1,
      totalSpent: 0,
      lastVisit: new Date().toISOString().split('T')[0],
      ...customer
    };
    customers.push(newCustomer);
    localStorage.setItem('pharmacy_customers', JSON.stringify(customers));
    return newCustomer;
  }

  updateOrCreateCustomer(name, phone, amount) {
    const customers = this.getCustomers();
    const existingCustomer = customers.find(c => c.phone === phone || c.name === name);
    
    if (existingCustomer) {
      existingCustomer.visits += 1;
      existingCustomer.totalSpent += amount;
      existingCustomer.lastVisit = new Date().toISOString().split('T')[0];
      localStorage.setItem('pharmacy_customers', JSON.stringify(customers));
      return existingCustomer;
    } else {
      return this.addCustomer({ name, phone, email: '', totalSpent: amount });
    }
  }

  updateCustomer(id, updates) {
    const customers = this.getCustomers();
    const index = customers.findIndex(c => c.id === id);
    if (index !== -1) {
      customers[index] = { ...customers[index], ...updates };
      localStorage.setItem('pharmacy_customers', JSON.stringify(customers));
      return customers[index];
    }
    return null;
  }

  deleteCustomer(id) {
    const customers = this.getCustomers().filter(c => c.id !== id);
    localStorage.setItem('pharmacy_customers', JSON.stringify(customers));
    return true;
  }

  // ============= PRESCRIPTIONS MANAGEMENT =============
  getPrescriptions() {
    return JSON.parse(localStorage.getItem('pharmacy_prescriptions')) || [];
  }

  getPrescriptionById(id) {
    const prescriptions = this.getPrescriptions();
    return prescriptions.find(p => p.id === id);
  }

  getPrescriptionsByCustomerId(customerId) {
    const prescriptions = this.getPrescriptions();
    return prescriptions.filter(p => p.customerId === customerId);
  }

  getActivePrescriptions() {
    const prescriptions = this.getPrescriptions();
    const today = new Date();
    return prescriptions.filter(p => {
      const expiryDate = new Date(p.expiryDate);
      return expiryDate >= today && p.status === 'active';
    });
  }

  addPrescription(prescription) {
    const prescriptions = this.getPrescriptions();
    const newPrescription = {
      id: Math.max(...prescriptions.map(p => p.id), 0) + 1,
      date: new Date().toISOString().split('T')[0],
      status: 'active',
      ...prescription
    };
    prescriptions.push(newPrescription);
    localStorage.setItem('pharmacy_prescriptions', JSON.stringify(prescriptions));
    return newPrescription;
  }

  updatePrescription(id, updates) {
    const prescriptions = this.getPrescriptions();
    const index = prescriptions.findIndex(p => p.id === id);
    if (index !== -1) {
      prescriptions[index] = { ...prescriptions[index], ...updates };
      localStorage.setItem('pharmacy_prescriptions', JSON.stringify(prescriptions));
      return prescriptions[index];
    }
    return null;
  }

  deletePrescription(id) {
    const prescriptions = this.getPrescriptions().filter(p => p.id !== id);
    localStorage.setItem('pharmacy_prescriptions', JSON.stringify(prescriptions));
    return true;
  }

  // ============= ANALYTICS =============
  getTotalRevenue() {
    const transactions = this.getTransactions();
    return transactions.reduce((sum, t) => sum + t.total, 0);
  }

  getTotalTransactions() {
    return this.getTransactions().length;
  }

  getTotalCustomers() {
    return this.getCustomers().length;
  }

  getTotalMedicines() {
    const medicines = this.getMedicines();
    return medicines.reduce((sum, m) => sum + m.quantity, 0);
  }

  getExpiringMedicines(daysThreshold = 30) {
    const medicines = this.getMedicines();
    const today = new Date();
    const threshold = new Date(today.getTime() + daysThreshold * 24 * 60 * 60 * 1000);
    
    return medicines.filter(m => {
      const expiryDate = new Date(m.expiryDate);
      return expiryDate <= threshold && expiryDate > today;
    });
  }

  getLowStockMedicines(threshold = 10) {
    const medicines = this.getMedicines();
    return medicines.filter(m => m.quantity > 0 && m.quantity <= threshold);
  }

  getOutOfStockMedicines() {
    const medicines = this.getMedicines();
    return medicines.filter(m => m.quantity === 0);
  }

  getMonthlySales(year, month) {
    const transactions = this.getTransactions();
    return transactions.filter(t => {
      const date = new Date(t.date);
      return date.getFullYear() === year && date.getMonth() === month;
    });
  }

  getTopMedicines(limit = 5) {
    const transactions = this.getTransactions();
    const medicineCount = {};

    transactions.forEach(t => {
      t.medicines.forEach(m => {
        medicineCount[m.name] = (medicineCount[m.name] || 0) + m.quantity;
      });
    });

    return Object.entries(medicineCount)
      .map(([name, quantity]) => ({ name, quantity }))
      .sort((a, b) => b.quantity - a.quantity)
      .slice(0, limit);
  }

  // ============= DATA MANAGEMENT =============
  exportData() {
    return {
      medicines: this.getMedicines(),
      items: this.getItems(),
      transactions: this.getTransactions(),
      customers: this.getCustomers(),
      exportDate: new Date().toISOString()
    };
  }

  // ============= ITEMS MANAGEMENT =============
  getItems() {
    return JSON.parse(localStorage.getItem('pharmacy_items')) || [];
  }

  getItemById(id) {
    const items = this.getItems();
    return items.find(i => i.id === id);
  }

  getItemsByCategory(category) {
    const items = this.getItems();
    return items.filter(i => i.category === category);
  }

  addItem(item) {
    const items = this.getItems();
    const newItem = {
      id: Math.max(...items.map(i => i.id), 0) + 1,
      ...item,
      quantity: parseInt(item.quantity),
      price: parseFloat(item.price),
      expiryDate: item.expiryDate || ''
    };
    items.push(newItem);
    localStorage.setItem('pharmacy_items', JSON.stringify(items));
    return newItem;
  }

  updateItem(id, updates) {
    const items = this.getItems();
    const index = items.findIndex(i => i.id === id);
    if (index !== -1) {
      if (updates.quantity) updates.quantity = parseInt(updates.quantity);
      if (updates.price) updates.price = parseFloat(updates.price);
      items[index] = { ...items[index], ...updates };
      localStorage.setItem('pharmacy_items', JSON.stringify(items));
      return items[index];
    }
    return null;
  }

  deleteItem(id) {
    const items = this.getItems().filter(i => i.id !== id);
    localStorage.setItem('pharmacy_items', JSON.stringify(items));
    return true;
  }

  updateItemQuantity(itemName, quantityChange) {
    const items = this.getItems();
    const item = items.find(i => i.name === itemName);
    if (item) {
      item.quantity += quantityChange;
      if (item.quantity < 0) item.quantity = 0;
      localStorage.setItem('pharmacy_items', JSON.stringify(items));
      return item;
    }
    return null;
  }

  getLowStockItems(threshold = 10) {
    const items = this.getItems();
    return items.filter(i => i.quantity > 0 && i.quantity <= threshold);
  }

  getOutOfStockItems() {
    const items = this.getItems();
    return items.filter(i => i.quantity === 0);
  }

  getExpiredItems() {
    const items = this.getItems();
    const today = new Date();
    return items.filter(i => {
      if (!i.expiryDate) return false;
      const expiryDate = new Date(i.expiryDate);
      return expiryDate < today;
    });
  }

  getExpiringItems(daysThreshold = 30) {
    const items = this.getItems();
    const today = new Date();
    const threshold = new Date(today.getTime() + daysThreshold * 24 * 60 * 60 * 1000);
    
    return items.filter(i => {
      if (!i.expiryDate) return false;
      const expiryDate = new Date(i.expiryDate);
      return expiryDate <= threshold && expiryDate > today;
    });
  }

  // ============= ROLES MANAGEMENT =============
  getRoles() {
    return JSON.parse(localStorage.getItem('pharmacy_roles')) || [];
  }

  getRoleById(id) {
    const roles = this.getRoles();
    return roles.find(r => r.id === id);
  }

  getRoleByName(name) {
    const roles = this.getRoles();
    return roles.find(r => r.name === name);
  }

  addRole(role) {
    const roles = this.getRoles();
    const newRole = {
      id: Math.max(...roles.map(r => r.id), 0) + 1,
      ...role,
      createdAt: new Date().toISOString()
    };
    roles.push(newRole);
    localStorage.setItem('pharmacy_roles', JSON.stringify(roles));
    return newRole;
  }

  updateRole(id, updates) {
    const roles = this.getRoles();
    const index = roles.findIndex(r => r.id === id);
    if (index !== -1) {
      roles[index] = { ...roles[index], ...updates };
      localStorage.setItem('pharmacy_roles', JSON.stringify(roles));
      return roles[index];
    }
    return null;
  }

  deleteRole(id) {
    // Don't allow deleting if users are assigned to this role
    const users = this.getUsers();
    if (users.some(u => u.roleId === id)) {
      showNotification('⚠️ Cannot delete role. Users are assigned to this role.', 'warning');
      return false;
    }
    const roles = this.getRoles().filter(r => r.id !== id);
    localStorage.setItem('pharmacy_roles', JSON.stringify(roles));
    return true;
  }

  // ============= USERS MANAGEMENT =============
  getUsers() {
    return JSON.parse(localStorage.getItem('pharmacy_users')) || [];
  }

  getUserById(id) {
    const users = this.getUsers();
    return users.find(u => u.id === id);
  }

  getUserByUsername(username) {
    const users = this.getUsers();
    return users.find(u => u.username === username);
  }

  addUser(user) {
    const users = this.getUsers();
    const newUser = {
      id: Math.max(...users.map(u => u.id), 0) + 1,
      password: this.hashPassword(user.password),
      status: 'active',
      createdAt: new Date().toISOString(),
      ...user
    };
    users.push(newUser);
    localStorage.setItem('pharmacy_users', JSON.stringify(users));
    return { ...newUser, password: undefined };
  }

  updateUser(id, updates) {
    const users = this.getUsers();
    const index = users.findIndex(u => u.id === id);
    if (index !== -1) {
      const updatedUser = { ...users[index], ...updates };
      if (updates.password) {
        updatedUser.password = this.hashPassword(updates.password);
      }
      users[index] = updatedUser;
      localStorage.setItem('pharmacy_users', JSON.stringify(users));
      return { ...updatedUser, password: undefined };
    }
    return null;
  }

  deleteUser(id) {
    const users = this.getUsers().filter(u => u.id !== id);
    localStorage.setItem('pharmacy_users', JSON.stringify(users));
    return true;
  }

  // Simple password hashing (for development)
  hashPassword(password) {
    return btoa(password); // Base64 encoding (for demo purposes only)
  }

  verifyPassword(plainPassword, hashedPassword) {
    return btoa(plainPassword) === hashedPassword;
  }

  // ============= AUTHENTICATION =============
  authenticateUser(username, password) {
    const user = this.getUserByUsername(username);
    if (user && this.verifyPassword(password, user.password) && user.status === 'active') {
      const role = this.getRoleById(user.roleId);
      return { ...user, password: undefined, role };
    }
    return null;
  }

  clearAllData() {
    if (confirm('⚠️ This will delete ALL data. Are you sure?')) {
      localStorage.removeItem('pharmacy_medicines');
      localStorage.removeItem('pharmacy_transactions');
      localStorage.removeItem('pharmacy_customers');
      this.initializeDatabase();
      return true;
    }
    return false;
  }
}

// Create global database instance
const db = new PharmacyDatabase();
