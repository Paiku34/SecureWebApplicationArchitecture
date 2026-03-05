/**
 * Password Strength Meter - Real-time validation (Register)
 * Logica unificata: requisiti obbligatori + punteggio 100/100 per sbloccare l'invio.
 */
document.addEventListener('DOMContentLoaded', function() {
    const newPass   = document.getElementById('new_password');
    const indicator = document.getElementById('strength-indicator');
    const barFill   = document.getElementById('strength-bar-fill');
    const strengthLabel    = document.getElementById('strength-label');
    const strengthScore    = document.getElementById('strength-score');
    const strengthFeedback = document.getElementById('strength-feedback');
    const submitBtn = document.getElementById('submit-btn');

    const reqLength = document.getElementById('req-length');
    const reqLower  = document.getElementById('req-lower');
    const reqUpper  = document.getElementById('req-upper');
    const reqNumber = document.getElementById('req-number');
    const reqSymbol = document.getElementById('req-symbol');

    if (!newPass || !indicator) return;

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

        const len       = pwd.length;
        const hasLength = len >= 12;
        const hasLower  = /[a-z]/.test(pwd);
        const hasUpper  = /[A-Z]/.test(pwd);
        const hasNumber = /[0-9]/.test(pwd);
        const hasSymbol = /[^a-zA-Z0-9]/.test(pwd);

        updateRequirement(reqLength, hasLength);
        updateRequirement(reqLower,  hasLower);
        updateRequirement(reqUpper,  hasUpper);
        updateRequirement(reqNumber, hasNumber);
        updateRequirement(reqSymbol, hasSymbol);

        // Calcola punteggio (max 100)
        let score = 0;
        score += hasLength ? 40 : (len >= 10 ? 25 : 10);
        if (hasLower)  score += 10;
        if (hasUpper)  score += 10;
        if (hasNumber) score += 15;
        if (hasSymbol) score += 25;

        // Penalità
        let feedback = [];
        if (/(password|12345|qwerty|admin)/i.test(pwd)) { score -= 20; feedback.push("Evita parole comuni"); }
        if (/(.)\1{2,}/.test(pwd))                      { score -= 10; feedback.push("Evita ripetizioni"); }

        score = Math.max(0, Math.min(100, score));

        // Aggiorna indicatore (CSS class)
        indicator.className = 'strength-indicator show strength-' +
            (score === 100 ? 'forte' : (score >= 50 ? 'media' : 'debole'));

        // Aggiorna barra (CSS custom properties per CSP)
        if (barFill) {
            barFill.style.setProperty('--bar-width', score + '%');
            barFill.style.setProperty('--bar-color',
                score === 100 ? '#10b981' : (score >= 50 ? '#f59e0b' : '#dc2626'));
        }

        if (strengthLabel) strengthLabel.textContent =
            score === 100 ? '🟢 Forte' : (score >= 50 ? '🟡 Media' : '🔴 Debole');
        if (strengthScore) strengthScore.textContent = score + '/100';

        const missing = [];
        if (!hasLength) missing.push("min 12 caratteri");
        if (!hasLower)  missing.push("minuscole");
        if (!hasUpper)  missing.push("MAIUSCOLE");
        if (!hasNumber) missing.push("numeri");
        if (!hasSymbol) missing.push("simboli");

        const allFb = [...(missing.length ? ['Manca: ' + missing.join(', ')] : []), ...feedback];
        if (strengthFeedback) {
            strengthFeedback.textContent = allFb.length
                ? allFb.join('. ')
                : (score === 100 ? '✓ Password eccellente!' : 'Migliora la password');
        }

        return score;
    }

    function updateSubmitButton() {
        if (!submitBtn) return;
        const allValid =
            reqLength?.classList.contains('valid') &&
            reqLower?.classList.contains('valid')  &&
            reqUpper?.classList.contains('valid')  &&
            reqNumber?.classList.contains('valid') &&
            reqSymbol?.classList.contains('valid');
        submitBtn.disabled = !(currentScore === 100 && allValid);
    }

    newPass.addEventListener('input', function() {
        currentScore = checkPasswordStrength(this.value);
        updateSubmitButton();
    });
});
