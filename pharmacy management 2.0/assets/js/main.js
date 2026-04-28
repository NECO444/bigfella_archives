// Pharmacy Management System - Main JavaScript

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
  initializeNavigation();
  initializeModals();
  setupResponsiveMenu();
});

// Navigation functionality
function initializeNavigation() {
  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    link.addEventListener('click', function() {
      navLinks.forEach(l => l.classList.remove('active'));
      this.classList.add('active');
    });
  });
}

// Modal functionality
function initializeModals() {
  const modals = document.querySelectorAll('.modal');
  modals.forEach(modal => {
    modal.addEventListener('click', function(e) {
      if (e.target === this) {
        this.classList.remove('show');
      }
    });
  });

  const closeButtons = document.querySelectorAll('.modal-close');
  closeButtons.forEach(btn => {
    btn.addEventListener('click', function() {
      this.closest('.modal').classList.remove('show');
    });
  });
}

// Responsive mobile menu
function setupResponsiveMenu() {
  const sidebar = document.querySelector('.sidebar');
  const toggleButton = document.querySelector('.menu-toggle');
  
  if (toggleButton && sidebar) {
    toggleButton.addEventListener('click', function() {
      sidebar.classList.toggle('mobile-open');
    });

    // Close sidebar when clicking on a nav link
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
      link.addEventListener('click', function() {
        sidebar.classList.remove('mobile-open');
      });
    });
  }
}

// Form validation
function validateForm(formId) {
  const form = document.getElementById(formId);
  if (!form) return true;

  const inputs = form.querySelectorAll('[required]');
  let isValid = true;

  inputs.forEach(input => {
    if (!input.value.trim()) {
      input.classList.add('error');
      isValid = false;
    } else {
      input.classList.remove('error');
    }
  });

  return isValid;
}

// Search functionality
function setupSearch(inputId, tableId) {
  const searchInput = document.getElementById(inputId);
  const table = document.getElementById(tableId);

  if (!searchInput || !table) return;

  searchInput.addEventListener('keyup', function() {
    const filter = this.value.toLowerCase();
    const rows = table.querySelectorAll('tbody tr');

    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(filter) ? '' : 'none';
    });
  });
}

// Notification handler
function showNotification(message, type = 'success') {
  const alert = document.createElement('div');
  alert.className = `alert alert-${type}`;
  alert.innerHTML = `
    <span class="alert-icon">${getAlertIcon(type)}</span>
    <span>${message}</span>
  `;

  const container = document.querySelector('.content') || document.body;
  container.insertAdjacentElement('afterbegin', alert);

  // Auto-remove after 5 seconds
  setTimeout(() => alert.remove(), 5000);
}

function getAlertIcon(type) {
  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ'
  };
  return icons[type] || 'ℹ';
}

// Date formatting
function formatDate(date) {
  return new Date(date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

// Currency formatting
function formatCurrency(amount) {
  return 'MK ' + new Intl.NumberFormat('en-US').format(amount.toFixed(2));
}

// Local storage helpers
const storage = {
  set: (key, value) => {
    localStorage.setItem(key, JSON.stringify(value));
  },
  get: (key) => {
    const item = localStorage.getItem(key);
    return item ? JSON.parse(item) : null;
  },
  remove: (key) => {
    localStorage.removeItem(key);
  },
  clear: () => {
    localStorage.clear();
  }
};

// Theme toggle
function toggleTheme() {
  const body = document.body;
  const currentTheme = storage.get('theme') || 'light';
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  
  body.setAttribute('data-theme', newTheme);
  storage.set('theme', newTheme);
}

// Page utilities
function printElement(elementId) {
  const element = document.getElementById(elementId);
  if (!element) return;

  const printWindow = window.open('', '_blank');
  printWindow.document.write(element.innerHTML);
  printWindow.document.close();
  printWindow.print();
}

function exportToCSV(tableId, filename = 'export.csv') {
  const table = document.getElementById(tableId);
  if (!table) return;

  let csv = [];
  const rows = table.querySelectorAll('tr');

  rows.forEach(row => {
    const cols = row.querySelectorAll('td, th');
    const csvRow = Array.from(cols).map(col => {
      return '"' + col.textContent.trim().replace(/"/g, '""') + '"';
    });
    csv.push(csvRow.join(','));
  });

  const csvContent = csv.join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv' });
  const link = document.createElement('a');
  link.href = window.URL.createObjectURL(blob);
  link.download = filename;
  link.click();
}

// API mock helpers (for development)
const mockAPI = {
  getMedicines: () => {
    return [
      { id: 1, name: 'Aspirin 500mg', batch: 'ASP-2026-001', quantity: 250, price: 2.50 },
      { id: 2, name: 'Vitamin D3', batch: 'VIT-2026-045', quantity: 45, price: 5.20 },
      { id: 3, name: 'Amoxicillin 250mg', batch: 'AMX-2026-012', quantity: 8, price: 3.75 }
    ];
  },
  getSales: () => {
    return [
      { id: 1, date: '2026-04-27', customer: 'Ahmed Khan', amount: 45.00 },
      { id: 2, date: '2026-04-27', customer: 'Fatima Ali', amount: 28.50 },
      { id: 3, date: '2026-04-26', customer: 'Muhammad Hassan', amount: 82.00 }
    ];
  }
};

// Utility functions
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// Log helper (development)
const logger = {
  info: (msg) => console.log('[INFO]', msg),
  warn: (msg) => console.warn('[WARN]', msg),
  error: (msg) => console.error('[ERROR]', msg),
  debug: (msg) => console.debug('[DEBUG]', msg)
};
