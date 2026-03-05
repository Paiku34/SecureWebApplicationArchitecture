/**
 * profile.js - JavaScript per la pagina profilo utente
 * 
 * Gestisce l'interazione per copiare il nome utente negli appunti
 * CSP-compliant: nessun inline event handler
 */

document.addEventListener('DOMContentLoaded', function() {
    // Gestione copy-to-clipboard per username
    const copyButtons = document.querySelectorAll('[data-action="copy-username"]');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const username = this.getAttribute('data-username');
            
            if (!username) {
                console.error('Username non trovato');
                return;
            }
            
            try {
                // Usa l'API Clipboard moderna
                await navigator.clipboard.writeText(username);
                
                // Feedback visivo: cambia l'icona
                const originalIcon = this.textContent;
                this.textContent = 'check';
                
                // Ripristina l'icona dopo 2 secondi
                setTimeout(() => {
                    this.textContent = originalIcon;
                }, 2000);
                
            } catch (err) {
                // Fallback per browser più vecchi o permessi negati
                console.error('Errore nella copia:', err);
                
                // Fallback: crea temporaneamente un textarea nascosto
                const textarea = document.createElement('textarea');
                textarea.value = username;
                textarea.style.position = 'absolute';
                textarea.style.left = '-9999px';
                document.body.appendChild(textarea);
                textarea.select();
                
                try {
                    document.execCommand('copy');
                    
                    // Feedback visivo
                    const originalIcon = this.textContent;
                    this.textContent = 'check';
                    setTimeout(() => {
                        this.textContent = originalIcon;
                    }, 2000);
                } catch (fallbackErr) {
                    console.error('Fallback copy fallito:', fallbackErr);
                }
                
                document.body.removeChild(textarea);
            }
        });
    });
});
