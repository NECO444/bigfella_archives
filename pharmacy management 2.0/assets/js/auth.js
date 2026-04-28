// Pharmacy Management System - Authentication & Authorization

// Current user session
let currentUser = null;

// Initialize authentication on page load
document.addEventListener('DOMContentLoaded', function() {
  restoreSession();
  checkAuthentication();
});

// ============= SESSION MANAGEMENT =============
function loginUser(username, password) {
  const user = db.authenticateUser(username, password);
  if (user) {
    currentUser = user;
    localStorage.setItem('pharmacy_current_user', JSON.stringify(user));
    return true;
  }
  return false;
}

function logoutUser() {
  currentUser = null;
  localStorage.removeItem('pharmacy_current_user');
  window.location.href = 'index.html';
}

function restoreSession() {
  const savedUser = localStorage.getItem('pharmacy_current_user');
  if (savedUser) {
    try {
      currentUser = JSON.parse(savedUser);
    } catch (e) {
      currentUser = null;
    }
  }
}

function getCurrentUser() {
  return currentUser;
}

function isLoggedIn() {
  return currentUser !== null;
}

// ============= ROLE-BASED ACCESS CONTROL =============
function hasPermission(permission) {
  if (!currentUser || !currentUser.role) return false;
  return currentUser.role.permissions && currentUser.role.permissions.includes(permission);
}

function hasAnyPermission(permissions) {
  return permissions.some(p => hasPermission(p));
}

function hasAllPermissions(permissions) {
  return permissions.every(p => hasPermission(p));
}

function isAdmin() {
  return currentUser && currentUser.role && currentUser.role.name === 'Admin';
}

function isPharmacist() {
  return currentUser && currentUser.role && currentUser.role.name === 'Pharmacist';
}

function isCashier() {
  return currentUser && currentUser.role && currentUser.role.name === 'Cashier';
}

function isManager() {
  return currentUser && currentUser.role && currentUser.role.name === 'Manager';
}

// ============= PAGE PROTECTION =============
function checkAuthentication() {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  
  // Allow access to login and settings pages without authentication for specific paths
  if (currentPage === 'index.html') {
    return; // Login page is public
  }

  // Check if user is authenticated
  if (!isLoggedIn()) {
    window.location.href = 'index.html';
    return;
  }

  // Page-specific permission checks
  const pagePermissions = {
    'inventory.html': ['view_inventory'],
    'sales.html': ['view_sales', 'create_sales'],
    'customers.html': ['view_all'],
    'reports.html': ['view_reports'],
    'settings.html': ['view_all'] // Settings accessible to all logged-in users
  };

  if (pagePermissions[currentPage]) {
    if (!hasAnyPermission(pagePermissions[currentPage]) && !isAdmin()) {
      showNotification('❌ Access Denied. You do not have permission to view this page.', 'error');
      setTimeout(() => {
        window.location.href = 'dashboard.html';
      }, 2000);
    }
  }
}

function requirePermission(permission) {
  if (!hasPermission(permission) && !isAdmin()) {
    return false;
  }
  return true;
}

function requireAnyPermission(permissions) {
  if (!hasAnyPermission(permissions) && !isAdmin()) {
    return false;
  }
  return true;
}

// ============= UI VISIBILITY CONTROL =============
function hideIfNoPermission(elementSelector, permission) {
  const element = document.querySelector(elementSelector);
  if (element && !hasPermission(permission) && !isAdmin()) {
    element.style.display = 'none';
  }
}

function showIfHasPermission(elementSelector, permission) {
  const element = document.querySelector(elementSelector);
  if (element && (hasPermission(permission) || isAdmin())) {
    element.style.display = '';
  } else if (element) {
    element.style.display = 'none';
  }
}

function updateUserProfile() {
  const userAvatar = document.querySelector('.user-avatar');
  const userName = document.querySelector('.user-info p:first-child');
  const userRole = document.querySelector('.user-info p:last-child');

  if (userAvatar && currentUser) {
    userAvatar.textContent = currentUser.fullName.split(' ').map(n => n[0]).join('').toUpperCase();
  }

  if (userName && currentUser) {
    userName.textContent = currentUser.fullName;
  }

  if (userRole && currentUser && currentUser.role) {
    userRole.textContent = currentUser.role.name;
  }
}

// Add logout button to navbar
function setupLogoutButton() {
  const navbar = document.querySelector('.navbar-right');
  if (navbar && isLoggedIn()) {
    // Remove existing logout button if any
    const existingLogout = navbar.querySelector('.logout-btn');
    if (existingLogout) existingLogout.remove();

    const logoutBtn = document.createElement('button');
    logoutBtn.className = 'logout-btn';
    logoutBtn.style.cssText = 'background: #ef4444; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; margin-left: 16px; font-weight: 500; font-size: 13px;';
    logoutBtn.textContent = ' Logout';
    logoutBtn.onclick = function() {
      if (confirm('Are you sure you want to logout?')) {
        logoutUser();
      }
    };
    navbar.appendChild(logoutBtn);
  }
}

// Update profile on page load
document.addEventListener('DOMContentLoaded', function() {
  if (isLoggedIn()) {
    updateUserProfile();
    setupLogoutButton();
  }
});
