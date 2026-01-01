// =========================================================
// SYSTEM INTERFACE — SCRIPT PRINCIPAL
// =========================================================

console.log('🖥️ SYSTEM INITIALIZED');

// ================= VARIABLES GLOBALES =================
let systemTime = new Date();
let notificationQueue = [];

// ================= INITIALISATION =================
document.addEventListener('DOMContentLoaded', function() {
    console.log('✓ DOM LOADED');
    
    // Initialiser les modules
    initNavigation();
    initAnimations();
    initNotifications();
    updateSystemTime();
    
    console.log('✓ ALL SYSTEMS OPERATIONAL');
});

// ================= NAVIGATION ACTIVE =================
function initNavigation() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.style.color = 'var(--ui-primary)';
            link.style.borderBottom = '1px solid var(--ui-primary)';
        }
    });
    
    console.log('✓ NAVIGATION INITIALIZED');
}

// ================= ANIMATIONS =================
function initAnimations() {
    // Animation fade-in pour les éléments
    const elements = document.querySelectorAll('.stat-card, .report-section, .admin-section');
    
    elements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            el.style.transition = 'all 0.6s ease';
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
        }, index * 100);
    });
    
    // Animation flicker pour les titres
    const titles = document.querySelectorAll('h2');
    titles.forEach(title => {
        title.style.animation = 'textFlicker 0.05s ease infinite';
    });
    
    console.log('✓ ANIMATIONS LOADED');
}

// ================= SYSTÈME DE NOTIFICATIONS =================
function initNotifications() {
    // Créer le conteneur de notifications
    if (!document.getElementById('notification-container')) {
        const container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            z-index: 10000;
            max-width: 400px;
        `;
        document.body.appendChild(container);
    }
    
    console.log('✓ NOTIFICATION SYSTEM READY');
}

function showNotification(message, type = 'info', duration = 4000) {
    const container = document.getElementById('notification-container');
    
    const colors = {
        'success': 'var(--ui-low)',
        'error': 'var(--ui-critical)',
        'warning': 'var(--ui-high)',
        'info': 'var(--ui-primary)'
    };
    
    const notification = document.createElement('div');
    notification.className = 'system-notification';
    notification.style.cssText = `
        background: rgba(5, 8, 12, 0.98);
        border: 1px solid ${colors[type]};
        padding: 1rem 1.5rem;
        margin-bottom: 1rem;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.75rem;
        letter-spacing: 1px;
        color: ${colors[type]};
        text-transform: uppercase;
        box-shadow: 0 0 20px rgba(127, 255, 212, 0.3);
        animation: slideInRight 0.3s ease;
        position: relative;
        overflow: hidden;
    `;
    
    // Barre de progression
    const progressBar = document.createElement('div');
    progressBar.style.cssText = `
        position: absolute;
        bottom: 0;
        left: 0;
        height: 2px;
        background: ${colors[type]};
        width: 100%;
        animation: progressBar ${duration}ms linear;
    `;
    
    notification.innerHTML = `<span>▸</span> ${message}`;
    notification.appendChild(progressBar);
    container.appendChild(notification);
    
    // Supprimer après duration
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, duration);
    
    console.log(`[${type.toUpperCase()}] ${message}`);
}

// ================= HORLOGE SYSTÈME =================
function updateSystemTime() {
    const timeElements = document.querySelectorAll('[data-system-time]');
    
    setInterval(() => {
        systemTime = new Date();
        const timeString = systemTime.toLocaleTimeString('fr-FR', { 
            hour: '2-digit', 
            minute: '2-digit',
            second: '2-digit'
        });
        
        timeElements.forEach(el => {
            el.textContent = timeString;
        });
    }, 1000);
    
    console.log('✓ SYSTEM CLOCK ACTIVE');
}

// ================= CHARGEMENT STATS API =================
async function loadSystemStats() {
    try {
        const response = await fetch('/api/statistics');
        const data = await response.json();
        
        // Mettre à jour les éléments
        updateStatElement('total', data.total_vulnerabilities);
        updateStatElement('critical', data.critical);
        updateStatElement('high', data.high);
        
        showNotification('Stats updated successfully', 'success');
        
    } catch (error) {
        console.error('ERROR LOADING STATS:', error);
        showNotification('Error loading statistics', 'error');
    }
}

function updateStatElement(id, value) {
    const element = document.querySelector(`[data-stat="${id}"]`);
    if (element) {
        // Animation du changement de valeur
        element.style.animation = 'statPulse 0.5s ease';
        setTimeout(() => {
            element.textContent = value;
        }, 100);
    }
}

// ================= COPIER DANS PRESSE-PAPIERS =================
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard', 'success', 2000);
    }).catch(err => {
        showNotification('Copy failed', 'error', 2000);
        console.error('CLIPBOARD ERROR:', err);
    });
}

// ================= RACCOURCIS CLAVIER =================
document.addEventListener('keydown', function(e) {
    // Ctrl+K : Focus recherche
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[type="text"], input[type="search"]');
        if (searchInput) {
            searchInput.focus();
            searchInput.select();
            showNotification('Search activated', 'info', 1500);
        }
    }
    
    // Ctrl+R : Rafraîchir stats
    if ((e.ctrlKey || e.metaKey) && e.key === 'r' && e.shiftKey) {
        e.preventDefault();
        loadSystemStats();
    }
});

// ================= SMOOTH SCROLL =================
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// ================= EFFETS VISUELS CRT =================
function addCRTFlicker() {
    setInterval(() => {
        if (Math.random() > 0.98) {
            document.body.style.opacity = '0.97';
            setTimeout(() => {
                document.body.style.opacity = '1';
            }, 50);
        }
    }, 100);
}

// Activer le flicker CRT (subtil)
// addCRTFlicker(); // Décommentez si vous voulez l'effet

// ================= ANIMATIONS CSS DYNAMIQUES =================
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
    
    @keyframes progressBar {
        from { width: 100%; }
        to { width: 0%; }
    }
    
    @keyframes statPulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); color: var(--ui-primary); }
    }
    
    @keyframes textFlicker {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.98; }
    }
    
    /* Effet glow sur hover des liens */
    .nav-link {
        transition: all 0.3s ease;
    }
    
    .nav-link:hover {
        text-shadow: 0 0 10px var(--ui-primary);
    }
    
    /* Effet sur les boutons */
    .btn {
        position: relative;
        overflow: hidden;
        transition: all 0.3s ease;
    }
    
    .btn::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(127, 255, 212, 0.2), transparent);
        transition: left 0.5s ease;
    }
    
    .btn:hover::before {
        left: 100%;
    }
    
    /* Effet scanline dynamique sur les cards */
    .stat-card {
        position: relative;
        overflow: hidden;
    }
    
    .stat-card::before {
        content: '';
        position: absolute;
        top: -100%;
        left: 0;
        width: 100%;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--ui-primary), transparent);
        animation: scanline 3s ease-in-out infinite;
    }
    
    @keyframes scanline {
        0% { top: -100%; }
        50% { top: 100%; }
        100% { top: -100%; }
    }
    
    /* Cursor personnalisé */
    * {
        cursor: default;
    }
    
    a, button, .btn, input, select {
        cursor: crosshair;
    }
`;
document.head.appendChild(style);

// ================= DÉTECTION DE CONNEXION =================
window.addEventListener('online', () => {
    showNotification('Connection established', 'success');
});

window.addEventListener('offline', () => {
    showNotification('Connection lost', 'error');
});

// ================= EXPORTS GLOBAUX =================
window.systemInterface = {
    notify: showNotification,
    loadStats: loadSystemStats,
    copy: copyToClipboard
};

console.log('✓ SYSTEM INTERFACE LOADED');
console.log('━'.repeat(50));
console.log('TYPE: systemInterface.notify("message", "type")');
console.log('SHORTCUTS: Ctrl+K (search), Ctrl+Shift+R (refresh)');
console.log('━'.repeat(50));