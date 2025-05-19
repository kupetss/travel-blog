document.addEventListener('DOMContentLoaded', function() {
    // Login form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
            })
            .then(response => response.json())
            .then(data => {
                const messageEl = document.getElementById('message');
                messageEl.textContent = data.message;
                messageEl.className = data.success ? 'alert alert-success' : 'alert alert-danger';
                
                if (data.success && data.redirect) {
                    setTimeout(() => {
                        window.location.href = data.redirect;
                    }, 1000);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                const messageEl = document.getElementById('message');
                messageEl.textContent = 'An error occurred';
                messageEl.className = 'alert alert-danger';
            });
        });
    }
    
    // Register form
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
            })
            .then(response => response.json())
            .then(data => {
                const messageEl = document.getElementById('message');
                messageEl.textContent = data.message;
                messageEl.className = data.success ? 'alert alert-success' : 'alert alert-danger';
                
                if (data.success) {
                    setTimeout(() => {
                        window.location.href = '/login.html';
                    }, 1000);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                const messageEl = document.getElementById('message');
                messageEl.textContent = 'An error occurred';
                messageEl.className = 'alert alert-danger';
            });
        });
    }
});