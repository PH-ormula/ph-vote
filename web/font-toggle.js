document.addEventListener('DOMContentLoaded', function() {
    const root = document.documentElement;
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'font-toggle-btn';
    toggleBtn.innerHTML = 'Aa<span class="tooltip">change reading font</span>';
    
    // Load saved font preference or default to Futura
    const savedFont = localStorage.getItem('preferredFont') || 'Futura';
    root.style.setProperty('--current-font', `'${savedFont}'`);
    
    toggleBtn.addEventListener('click', function() {
        const currentFont = root.style.getPropertyValue('--current-font').replace(/['"]/g, '');
        const newFont = currentFont === 'Futura' ? 'Open Dyslexic Propo' : 'Futura';
        
        root.style.setProperty('--current-font', `'${newFont}'`);
        localStorage.setItem('preferredFont', newFont);
    });
    
    document.body.appendChild(toggleBtn);

    function updateTheme() {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.setAttribute('data-theme', 'light');
        }
    }
    updateTheme();
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', updateTheme);
    }
});
