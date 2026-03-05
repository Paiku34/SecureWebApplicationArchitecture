/**
 * Password Reset - Strength meter with requirements and confirmation
 * Valida password con requisiti specifici e verifica coincidenza
 */
document.addEventListener('DOMContentLoaded', function() {
    const newPass = document.getElementById('new_password');
    const confirmPass = document.getElementById('confirm_password');
    const indicator = document.getElementById('strength-indicator');
    const barFill = document.getElementById('strength-bar-fill');
    const strengthLabel = document.getElementById('strength-label');
    const strengthScore = document.getElementById('strength-score');
    const strengthFeedback = document.getElementById('strength-feedback');
    const confirmMatch = document.getElementById('confirm-match');
    const submitBtn = document.getElementById('submit-btn');
    
    // Elementi requisiti
    const reqLength = document.getElementById('req-length');
    const reqLower = document.getElementById('req-lower');
    const reqUpper = document.getElementById('req-upper');
    const reqNumber = document.getElementById('req-number');
    const reqSymbol = document.getElementById('req-symbol');
    
    // Verifica che tutti gli elementi esistano
    if (!newPass || !indicator) {
        return;
    }

    // Progressive enhancement: disable submit only when JS is active
    if (submitBtn) submitBtn.disabled = true;

    let currentScore = 0;
    
    function updateRequirement(el, valid) {
        if (!el) return;
        el.className = valid ? 'valid' : 'invalid';
        el.textContent = (valid ? '✓ ' : '✗ ') + el.textContent.substring(2);
    }
    
    function checkPasswordStrength(pwd) {
        if (!pwd.length) {
            indicator.classList.remove('show');
            return 0;
        }
        indicator.classList.add('show');
        
        let score = 0;
        let feedback = [];
        const len = pwd.length;
        
        // Verifica requisiti
        const hasLength = len >= 12;
        const hasLower = /[a-z]/.test(pwd);
        const hasUpper = /[A-Z]/.test(pwd);
        const hasNumber = /[0-9]/.test(pwd);
        const hasSymbol = /[^a-zA-Z0-9]/.test(pwd);
        
        updateRequirement(reqLength, hasLength);
        updateRequirement(reqLower, hasLower);
        updateRequirement(reqUpper, hasUpper);
        updateRequirement(reqNumber, hasNumber);
        updateRequirement(reqSymbol, hasSymbol);
        
        // Calcola punteggio (max 100)
        score += hasLength ? 40 : (len >= 10 ? 25 : 10);
        if (!hasLength) feedback.push("min 12 caratteri");

        if (hasLower)  score += 10; else feedback.push("minuscole");
        if (hasUpper)  score += 10; else feedback.push("MAIUSCOLE");
        if (hasNumber) score += 15; else feedback.push("numeri");
        if (hasSymbol) score += 25; else feedback.push("simboli");

        // Penalità
        if (/(password|12345|qwerty|admin)/i.test(pwd)) { score -= 20; feedback.push("Evita parole comuni"); }
        if (/(.)\1{2,}/.test(pwd))                      { score -= 10; feedback.push("Evita ripetizioni"); }

        score = Math.max(0, Math.min(100, score));

        // Aggiorna indicatore (CSS class unificata)
        indicator.className = 'strength-indicator show strength-' +
            (score === 100 ? 'forte' : (score >= 50 ? 'media' : 'debole'));

        // Usa CSS custom properties per CSP compliance
        if (barFill) {
            barFill.style.setProperty('--bar-width', score + '%');
            barFill.style.setProperty('--bar-color',
                score === 100 ? '#10b981' : (score >= 50 ? '#f59e0b' : '#dc2626'));
        }

        if (strengthLabel) strengthLabel.textContent =
            score === 100 ? '🟢 Forte' : (score >= 50 ? '🟡 Media' : '🔴 Debole');
        if (strengthScore) strengthScore.textContent = score + '/100';
        if (strengthFeedback) strengthFeedback.textContent = feedback.length
            ? 'Manca: ' + feedback.join(', ')
            : (score === 100 ? '✓ Password eccellente!' : 'Migliora la password');
        
        return score;
    }
    
    function checkConfirmMatch() {
        if (!confirmPass || !confirmMatch) return false;
        
        const pwd = newPass.value;
        const confirm = confirmPass.value;
        
        if (!confirm.length) {
            confirmMatch.textContent = '';
            return false;
        }
        
        if (pwd === confirm) {
            confirmMatch.className = 'confirm-match match';
            confirmMatch.textContent = '✓ Le password coincidono';
            return true;
        } else {
            confirmMatch.className = 'confirm-match no-match';
            confirmMatch.textContent = '✗ Le password non coincidono';
            return false;
        }
    }
    
    function updateSubmitButton() {
        if (!submitBtn) return;
        
        const scoreOk = currentScore === 100;
        const allCats = reqLength?.classList.contains('valid') &&
                        reqLower?.classList.contains('valid') &&
                        reqUpper?.classList.contains('valid') &&
                        reqNumber?.classList.contains('valid') &&
                        reqSymbol?.classList.contains('valid');
        const matchOk = newPass.value === confirmPass?.value && (confirmPass?.value.length || 0) > 0;
        
        submitBtn.disabled = !(scoreOk && allCats && matchOk);
    }
    
    newPass.addEventListener('input', function() {
        currentScore = checkPasswordStrength(this.value);
        checkConfirmMatch();
        updateSubmitButton();
    });
    
    if (confirmPass) {
        confirmPass.addEventListener('input', function() {
            checkConfirmMatch();
            updateSubmitButton();
        });
    }
});
