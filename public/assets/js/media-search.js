/**
 * Media Search - Real-time filtering
 */
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('mediaSearch');
    
    if (!searchInput) return;
    
    searchInput.addEventListener('input', function() {
        const query = this.value.toLowerCase();
        const rows = document.querySelectorAll('tbody tr');
        
        rows.forEach(row => {
            const title = row.querySelector('td:nth-child(1)')?.innerText.toLowerCase() || '';
            const author = row.querySelector('td:nth-child(2)')?.innerText.toLowerCase() || '';
            const access = row.querySelector('td:nth-child(3)')?.innerText.toLowerCase() || '';
            
            if (title.includes(query) || author.includes(query) || access.includes(query)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    });
});
