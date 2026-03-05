/**
 * View Lyrics - Copy and print functionality
 */
document.addEventListener('DOMContentLoaded', function() {
    // Copy lyrics to clipboard
    const copyButton = document.querySelector('[data-action="copy-lyrics"]');
    if (copyButton) {
        copyButton.addEventListener('click', function() {
            const lyricsContent = document.getElementById('lyrics-content');
            const copyIcon = document.getElementById('copy-icon');
            
            if (!lyricsContent) return;
            
            const lyricsText = lyricsContent.innerText;
            
            navigator.clipboard.writeText(lyricsText).then(() => {
                if (copyIcon) {
                    copyIcon.textContent = 'check';
                    setTimeout(() => {
                        copyIcon.textContent = 'content_copy';
                    }, 2000);
                }
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        });
    }
    
    // Print lyrics
    const printButton = document.querySelector('[data-action="print-lyrics"]');
    if (printButton) {
        printButton.addEventListener('click', function() {
            window.print();
        });
    }
});
