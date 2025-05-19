// Auth functions
const auth = {
    setToken: (token) => localStorage.setItem('authToken', token),
    getToken: () => localStorage.getItem('authToken'),
    removeToken: () => localStorage.removeItem('authToken'),
    isAuthenticated: () => !!localStorage.getItem('authToken'),
    authFetch: async (url, options = {}) => {
        const token = auth.getToken();
        options.headers = options.headers || {};
        options.headers['Authorization'] = token;
        
        try {
            const response = await fetch(url, options);
            if (response.status === 401) {
                auth.removeToken();
                window.location.href = '/login.html';
                return null;
            }
            return response;
        } catch (error) {
            console.error('Fetch error:', error);
            return null;
        }
    }
};

// Common function to handle form submission
async function handleFormSubmit(e, url, successCallback) {
    e.preventDefault();
    
    const form = e.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing...';
    
    try {
        const formData = new FormData(form);
        const response = await fetch(url, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        
        if (data.success) {
            if (successCallback) successCallback(data);
        } else {
            showMessage(data.message, false);
        }
    } catch (error) {
        console.error('Error:', error);
        showMessage('An error occurred', false);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

function showMessage(message, isSuccess) {
    const messageEl = document.getElementById('message');
    if (!messageEl) return;
    
    messageEl.textContent = message;
    messageEl.className = isSuccess ? 'alert alert-success' : 'alert alert-danger';
    messageEl.style.display = 'block';
    
    setTimeout(() => {
        messageEl.style.display = 'none';
    }, 5000);
}

// Login form
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        await handleFormSubmit(e, '/api/login', (data) => {
            auth.setToken(data.token);
            window.location.href = data.redirect || '/profile.html';
        });
    });
}

// Register form
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        await handleFormSubmit(e, '/api/register', (data) => {
            showMessage('Registration successful! Please login', true);
            setTimeout(() => {
                window.location.href = '/login.html';
            }, 1500);
        });
    });
}

// Profile page
if (document.getElementById('profilePhoto')) {
    // Check authentication
    if (!auth.isAuthenticated()) {
        window.location.href = '/login.html';
    }

    // Load profile data
    const loadProfile = async () => {
        try {
            const response = await auth.authFetch('/api/profile');
            if (!response) return;
            
            const data = await response.json();
            
            if (data && data.success) {
                document.getElementById('status').value = data.profile.status || '';
                document.getElementById('birthYear').value = data.profile.birth_year || '';
                document.getElementById('about').value = data.profile.about || '';
                
                if (data.profile.photo) {
                    document.getElementById('profilePhoto').src = 
                        `data:image/jpeg;base64,${data.profile.photo}`;
                }
            }
        } catch (error) {
            console.error('Failed to load profile:', error);
        }
    };

    // Upload photo
    document.getElementById('uploadBtn').addEventListener('click', async () => {
        const fileInput = document.getElementById('photoUpload');
        if (fileInput.files.length === 0) {
            showMessage('Please select a photo first', false);
            return;
        }

        const formData = new FormData();
        formData.append('photo', fileInput.files[0]);

        try {
            const response = await auth.authFetch('/api/upload-photo', {
                method: 'POST',
                body: formData
            });

            if (!response) return;
            
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('profilePhoto').src = 
                    `data:image/jpeg;base64,${data.photo}`;
                showMessage('Photo uploaded successfully!', true);
            } else {
                throw new Error(data.message || 'Failed to upload photo');
            }
        } catch (error) {
            console.error('Error:', error);
            showMessage(error.message, false);
        }
    });

    // Save profile
    const saveProfileForm = document.getElementById('saveProfileForm');
    if (saveProfileForm) {
        saveProfileForm.addEventListener('submit', async (e) => {
            await handleFormSubmit(e, '/api/save-profile', () => {
                showMessage('Profile saved successfully!', true);
                loadProfile();
            });
        });
    }

    // Logout
    document.getElementById('logoutBtn').addEventListener('click', () => {
        auth.removeToken();
        window.location.href = '/login.html';
    });

    // Initial load
    loadProfile();
}