/**
 * Admin Panel - Tab switching and confirmation dialogs
 */
document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    const tabButtons = document.querySelectorAll('[data-tab]');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            switchTab(tabName);
        });
    });
    
    function switchTab(tabName) {
        // Nascondi tutti i tab content
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Rimuovi classe active da tutti i bottoni
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        
        // Mostra il tab selezionato
        const selectedTab = document.getElementById(tabName + '-tab');
        if (selectedTab) {
            selectedTab.classList.add('active');
        }
        
        // Attiva il bottone corrispondente
        const activeButton = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeButton) {
            activeButton.classList.add('active');
        }
    }
    
    // Confirmation dialogs
    const confirmDeleteUser = document.querySelectorAll('[data-confirm="delete-user"]');
    confirmDeleteUser.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!confirm('Sei sicuro di voler eliminare questo utente?')) {
                e.preventDefault();
            }
        });
    });
    
    const confirmDeleteMedia = document.querySelectorAll('[data-confirm="delete-media"]');
    confirmDeleteMedia.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!confirm('Sei sicuro di voler eliminare questo media?')) {
                e.preventDefault();
            }
        });
    });
    
    const confirmMaintenance = document.querySelectorAll('[data-confirm="maintenance"]');
    confirmMaintenance.forEach(btn => {
        btn.addEventListener('click', function(e) {
            if (!confirm('Eseguire manutenzione completa del sistema?')) {
                e.preventDefault();
            }
        });
    });
    
    const confirmUnblock = document.querySelectorAll('[data-confirm="unblock"]');
    confirmUnblock.forEach(btn => {
        btn.addEventListener('click', function(e) {
            if (!confirm('Sbloccare questo utente?')) {
                e.preventDefault();
            }
        });
    });
});
