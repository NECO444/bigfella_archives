/* ================================================================
   VERTEX TECH SOLUTIONS — script.js
   Functions:
     0. Lucide icons   — render all <i data-lucide> tags
     1. Navbar         — scroll effects + active link highlight
     2. Mobile menu    — hamburger toggle
     3. Theme toggle   — light/dark mode + localStorage persistence
     4. Scroll reveal  — fade-in on viewport entry
     5. Count-up       — animate stat numbers
     6. Footer year    — auto-update copyright year
     7. Smooth scroll  — navbar-offset anchor scrolling
     8. Card tilt      — 3-D mouse-move effect (desktop only)
   ================================================================ */


/* ----------------------------------------------------------------
   0. LUCIDE ICONS
   Lucide's CDN script exposes a global `lucide` object.
   createIcons() finds every <i data-lucide="name"> in the DOM
   and replaces it with an inline <svg data-lucide="name">.
   We call it on DOMContentLoaded to guarantee the DOM is ready.
   ---------------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', function () {
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }
});

/* Extra safety: also run on window load for any slow-loading scripts */
window.addEventListener('load', function () {
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }
});


/* ----------------------------------------------------------------
   1. NAVBAR
   ---------------------------------------------------------------- */
(function initNavbar() {

  var navbar  = document.getElementById('navbar');
  var lastY   = window.scrollY;
  var ticking = false;

  function onScroll() {
    var y = window.scrollY;
    /* Frosted glass after 60px */
    navbar.classList.toggle('scrolled', y > 60);
    /* Hide when scrolling down fast; reveal on scroll up */
    if (y > lastY && y > 180) {
      navbar.classList.add('hidden');
    } else {
      navbar.classList.remove('hidden');
    }
    lastY = y;
    ticking = false;
  }

  window.addEventListener('scroll', function () {
    if (!ticking) { requestAnimationFrame(onScroll); ticking = true; }
  }, { passive: true });

  /* Highlight active nav link for the section currently mid-screen */
  var sections = document.querySelectorAll('section[id], footer[id]');
  var navLinks = document.querySelectorAll('.nav-link');

  new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        var id = entry.target.id;
        navLinks.forEach(function (link) {
          link.classList.toggle('active', link.getAttribute('href') === '#' + id);
        });
      }
    });
  }, { rootMargin: '-40% 0px -55% 0px' }).observe
    ? sections.forEach(function (s) {
        new IntersectionObserver(function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              var id = entry.target.id;
              navLinks.forEach(function (link) {
                link.classList.toggle('active', link.getAttribute('href') === '#' + id);
              });
            }
          });
        }, { rootMargin: '-40% 0px -55% 0px' }).observe(s);
      })
    : null;

})();


/* ----------------------------------------------------------------
   2. MOBILE MENU
   ---------------------------------------------------------------- */
(function initMobileMenu() {

  var hamburger  = document.getElementById('hamburger');
  var mobileMenu = document.getElementById('mobileMenu');
  var mobLinks   = document.querySelectorAll('.mob-link');
  if (!hamburger || !mobileMenu) return;

  function open() {
    mobileMenu.classList.add('open');
    hamburger.classList.add('open');
    hamburger.setAttribute('aria-expanded', 'true');
    mobileMenu.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }
  function close() {
    mobileMenu.classList.remove('open');
    hamburger.classList.remove('open');
    hamburger.setAttribute('aria-expanded', 'false');
    mobileMenu.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  hamburger.addEventListener('click', function () {
    mobileMenu.classList.contains('open') ? close() : open();
  });
  mobLinks.forEach(function (l) { l.addEventListener('click', close); });
  document.addEventListener('click', function (e) {
    if (!hamburger.contains(e.target) && !mobileMenu.contains(e.target)) close();
  });

})();


/* ----------------------------------------------------------------
   3. THEME TOGGLE
   The initial theme is set by the inline <script> in <head>.
   This function handles the button click + aria label sync.
   ---------------------------------------------------------------- */
(function initThemeToggle() {

  var html      = document.documentElement;
  var toggleBtn = document.getElementById('themeToggle');
  if (!toggleBtn) return;

  function syncLabel() {
    toggleBtn.setAttribute('aria-label',
      html.getAttribute('data-theme') === 'dark'
        ? 'Switch to light mode'
        : 'Switch to dark mode'
    );
  }

  function applyTheme(theme) {
    html.setAttribute('data-theme', theme);
    localStorage.setItem('vts-theme', theme);
    syncLabel();
    // Update icon
    var icon = document.getElementById('themeIcon');
    if (icon) {
      icon.setAttribute('data-lucide', theme === 'dark' ? 'sun' : 'moon');
      if (typeof lucide !== 'undefined') {
        lucide.createIcons();
      }
    }
  }

  syncLabel(); /* Sync on load */

  /* Set initial icon */
  var initialTheme = html.getAttribute('data-theme');
  var icon = document.getElementById('themeIcon');
  if (icon) {
    icon.setAttribute('data-lucide', initialTheme === 'dark' ? 'sun' : 'moon');
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  }

  toggleBtn.addEventListener('click', function () {
    var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);

    /* One-shot spin animation */
    toggleBtn.style.transition = 'transform 0.4s cubic-bezier(0.4,0,0.2,1)';
    toggleBtn.style.transform  = 'rotate(360deg) scale(1.15)';
    setTimeout(function () {
      toggleBtn.style.transition = '';
      toggleBtn.style.transform  = '';
    }, 420);
  });

  /* Follow OS changes only if user hasn't set a manual preference */
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function (e) {
      if (!localStorage.getItem('vts-theme')) applyTheme(e.matches ? 'light' : 'dark');
    });
  }

})();


/* ----------------------------------------------------------------
   4. SCROLL REVEAL
   Adds .visible to .reveal elements as they enter the viewport.
   ---------------------------------------------------------------- */
(function initScrollReveal() {

  var els = document.querySelectorAll('.reveal');
  if (!els.length) return;

  if (!('IntersectionObserver' in window)) {
    /* Fallback: show everything immediately */
    els.forEach(function (el) { el.classList.add('visible'); });
    return;
  }

  var observer = new IntersectionObserver(function (entries, obs) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        var delay = parseInt(entry.target.dataset.delay || '0', 10);
        setTimeout(function () {
          entry.target.classList.add('visible');
        }, delay);
        obs.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  els.forEach(function (el) { observer.observe(el); });

})();


/* ----------------------------------------------------------------
   5. COUNT-UP ANIMATION
   ---------------------------------------------------------------- */
(function initCountUp() {

  var statEls = document.querySelectorAll('.stat-number');
  var section = document.querySelector('.about-stats');
  if (!statEls.length || !section) return;

  function countUp(el, target) {
    var start = null;
    var duration = 1600;
    function step(ts) {
      if (!start) start = ts;
      var progress = Math.min((ts - start) / duration, 1);
      var eased    = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(target * eased);
      if (progress < 1) requestAnimationFrame(step);
      else el.textContent = target;
    }
    requestAnimationFrame(step);
  }

  var fired = false;
  new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting && !fired) {
        fired = true;
        statEls.forEach(function (el) {
          var t = parseInt(el.dataset.target, 10);
          if (!isNaN(t)) countUp(el, t);
        });
      }
    });
  }, { threshold: 0.3 }).observe(section);

})();


/* ----------------------------------------------------------------
   6. FOOTER YEAR
   ---------------------------------------------------------------- */
(function () {
  var el = document.getElementById('year');
  if (el) el.textContent = new Date().getFullYear();
})();


/* ----------------------------------------------------------------
   7. SMOOTH SCROLL
   Compensates for the fixed navbar when jumping to anchors.
   ---------------------------------------------------------------- */
(function initSmoothScroll() {

  var OFFSET = 80;
  document.querySelectorAll('a[href^="#"]').forEach(function (a) {
    a.addEventListener('click', function (e) {
      var id     = this.getAttribute('href').slice(1);
      var target = document.getElementById(id);
      if (!target) return;
      e.preventDefault();
      window.scrollTo({
        top: target.getBoundingClientRect().top + window.scrollY - OFFSET,
        behavior: 'smooth'
      });
    });
  });

})();


/* ----------------------------------------------------------------
   9. MAILTO LINKS
   Opens Gmail compose in a new tab (works even without a default
   mail client configured on the device).
   ---------------------------------------------------------------- */
(function initMailtoLinks() {
  var EMAIL = 'vertextech265@gmail.com';
  document.querySelectorAll('a[href^="mailto:"]').forEach(function (a) {
    a.addEventListener('click', function (e) {
      e.preventDefault();
      var gmailUrl = 'https://mail.google.com/mail/?view=cm&to=' + EMAIL;
      window.open(gmailUrl, '_blank');
    });
  });
})();


/* ----------------------------------------------------------------
   8. CARD TILT (desktop only)
   ---------------------------------------------------------------- */
(function initCardTilt() {

  if (window.matchMedia('(pointer: coarse)').matches) return;

  document.querySelectorAll('.card').forEach(function (card) {
    var MAX = 8;

    card.addEventListener('mouseenter', function () {
      card.style.transition = 'transform 0.05s linear';
    });
    card.addEventListener('mousemove', function (e) {
      var r  = card.getBoundingClientRect();
      var nx =  (e.clientX - (r.left + r.width  / 2)) / (r.width  / 2);
      var ny = -(e.clientY - (r.top  + r.height / 2)) / (r.height / 2);
      card.style.transform =
        'perspective(900px) rotateX(' + (ny * MAX) + 'deg) rotateY(' + (nx * MAX) + 'deg) translateY(-6px)';
    });
    card.addEventListener('mouseleave', function () {
      card.style.transition = 'transform 0.45s ease';
      card.style.transform  = '';
      setTimeout(function () { card.style.transition = ''; }, 450);
    });
  });

})();


/* ----------------------------------------------------------------
   9. CONTACT FORM — Formspree submission with privacy check
   ---------------------------------------------------------------- */
(function initContactForm() {
  var form = document.getElementById('contactForm');
  if (!form) return;

  var privacyCheckbox = document.getElementById('cf-privacy');
  var privacyError    = document.getElementById('privacy-error');
  var successMsg      = document.getElementById('form-success');
  var submitBtn       = document.getElementById('submitBtn');

  /* Show/hide error live as user toggles */
  if (privacyCheckbox && privacyError) {
    privacyCheckbox.addEventListener('change', function () {
      if (this.checked) privacyError.classList.remove('visible');
    });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();

    /* Privacy gate */
    if (!privacyCheckbox || !privacyCheckbox.checked) {
      privacyError.classList.add('visible');
      privacyCheckbox.closest('.privacy-toggle-wrap').scrollIntoView({ behavior: 'smooth', block: 'center' });
      if (typeof lucide !== 'undefined') lucide.createIcons();
      return;
    }
    privacyError.classList.remove('visible');

    /* Loading state */
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Sending…';

    if (!document.getElementById('spin-style')) {
      var s = document.createElement('style');
      s.id = 'spin-style';
      s.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
      document.head.appendChild(s);
    }

    fetch(form.action, {
      method: 'POST',
      body: new FormData(form),
      headers: { 'Accept': 'application/json' }
    })
    .then(function (res) {
      if (res.ok) {
        form.reset();
        successMsg.style.display = 'flex';
        submitBtn.innerHTML = '<i data-lucide="check-circle" aria-hidden="true"></i> Sent!';
        if (typeof lucide !== 'undefined') lucide.createIcons();
        setTimeout(function () {
          successMsg.style.display = 'none';
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i data-lucide="send" aria-hidden="true"></i> Send Message <span class="btn-shimmer"></span>';
          if (typeof lucide !== 'undefined') lucide.createIcons();
        }, 5000);
      } else { throw new Error('Server error'); }
    })
    .catch(function () {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i data-lucide="alert-circle" aria-hidden="true"></i> Failed — try again';
      if (typeof lucide !== 'undefined') lucide.createIcons();
      setTimeout(function () {
        submitBtn.innerHTML = '<i data-lucide="send" aria-hidden="true"></i> Send Message <span class="btn-shimmer"></span>';
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }, 3000);
    });
  });
})();