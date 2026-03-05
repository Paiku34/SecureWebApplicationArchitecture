/**
 * upload.js - JavaScript per la pagina upload
 * 
 * Gestisce:
 * - Dismissione degli alert di successo
 * - Comportamento del bottone Annulla
 * - Visualizzazione nome file selezionato
 * CSP-compliant: nessun inline event handler
 */

document.addEventListener('DOMContentLoaded', function() {
    // Gestione dismissione success alert
    const alertCloseBtn = document.querySelector('[data-action="close-alert"]');
    if (alertCloseBtn) {
        alertCloseBtn.addEventListener('click', function() {
            const alertElement = document.getElementById('success-alert');
            if (alertElement) {
                alertElement.style.display = 'none';
            }
        });
    }
    
    // Gestione bottone Annulla
    const cancelBtn = document.querySelector('[data-action="cancel-upload"]');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function() {
            window.location.href = 'dashboard.php';
        });
    }
    
    // Gestione visualizzazione nome file per audio
    const audioFileInput = document.getElementById('dropzone-file-audio');
    if (audioFileInput) {
        audioFileInput.addEventListener('change', function() {
            updateFileName(this, 'audio-file-name');
        });
    }
    
    // Gestione visualizzazione nome file per lyrics
    const lyricsFileInput = document.getElementById('dropzone-file-lyrics');
    if (lyricsFileInput) {
        lyricsFileInput.addEventListener('change', function() {
            updateFileName(this, 'lyrics-file-name');
        });
    }
});

/**
 * Aggiorna l'elemento con il nome del file selezionato
 * @param {HTMLInputElement} input - Input element del file
 * @param {string} targetId - ID dell'elemento dove mostrare il nome del file
 */
function updateFileName(input, targetId) {
    const targetElement = document.getElementById(targetId);
    if (!targetElement) return;
    
    if (input.files && input.files.length > 0) {
        const fileName = input.files[0].name;
        targetElement.textContent = fileName;
        targetElement.classList.add('font-medium', 'text-primary');
    } else {
        targetElement.textContent = '';
        targetElement.classList.remove('font-medium', 'text-primary');
    }
}

