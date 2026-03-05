/**
 * Flash Messages - Auto-dismiss and close functionality
 */
document.addEventListener('DOMContentLoaded', function() {
    const flashAlert = document.getElementById('flash-alert');
    
    if (flashAlert) {
        // Auto-dismiss dopo 8 secondi
        setTimeout(() => {
            flashAlert.classList.add('fade-out');
            setTimeout(() => flashAlert.remove(), 300);
        }, 8000);
        
        // Gestione pulsante close
        const closeBtn = flashAlert.querySelector('.flash-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', function() {
                flashAlert.classList.add('fade-out');
                setTimeout(() => flashAlert.remove(), 300);
            });
        }
    }
});
