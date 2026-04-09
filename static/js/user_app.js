let currentUser = null;
let authToken = localStorage.getItem('iitm_token');

document.addEventListener('DOMContentLoaded', () => {
    const userStr = localStorage.getItem('iitm_user');
    if (!authToken || !userStr) {
        window.location.href = '/static/user_login.html';
        return;
    }
    currentUser = JSON.parse(userStr);
    
    // Check Role
    if(currentUser.role === 'admin') {
        // Admin allowed, show admin switch button
        const sidebar = document.querySelector('.nav-pills');
        const adminBtn = document.createElement('li');
        adminBtn.className = 'nav-item mt-3 pt-3 border-top';
        adminBtn.innerHTML = `
            <a href="/static/index.html" class="nav-link text-danger fw-bold">
                <i class="fas fa-user-shield me-2"></i> Admin Console
            </a>`;
        sidebar.appendChild(adminBtn);
    }

    // Init UI
    document.getElementById('sidebar_username').innerText = currentUser.name;
    loadProfileData();
    loadUserDashboardStats(); // Load stats for dashboard
    showSection('dashboard'); // Default to Dashboard
});

function logout() {
    localStorage.removeItem('iitm_token');
    localStorage.removeItem('iitm_user');
    window.location.href = '/static/user_login.html';
}

function showSection(id) {
    document.querySelectorAll('[id^="section_"]').forEach(el => el.classList.add('d-none'));
    document.getElementById(`section_${id}`).classList.remove('d-none');
    
    // Nav Active State
    document.querySelectorAll('.sidebar .nav-link').forEach(el => el.classList.remove('active'));
    const link = Array.from(document.querySelectorAll('.sidebar .nav-link')).find(el => el.getAttribute('onclick')?.includes(id));
    if(link) link.classList.add('active');

    if(id === 'my_requests') {
        loadRequests();
        startRequestsPolling();
    } else if (id === 'dashboard') {
        loadUserDashboardStats(); // Refresh stats when dashboard is shown
        stopRequestsPolling();
    } else {
        stopRequestsPolling();
    }
}

let requestsInterval = null;
function startRequestsPolling() {
    if(requestsInterval) clearInterval(requestsInterval);
    requestsInterval = setInterval(loadRequests, 5000);
}

function stopRequestsPolling() {
    if(requestsInterval) clearInterval(requestsInterval);
}

// Wizard Logic
function nextStep(step) {
    if(step === 2) {
        if(!document.getElementById('req_title').value) return alert("Project Name Required");
        if(!document.getElementById('req_poc_name').value) return alert("POC Name Required");
    }
    
    document.querySelectorAll('.step-content').forEach(el => el.classList.add('d-none'));
    document.getElementById(`step${step}`).classList.remove('d-none');
    
    // Indicators
    for(let i=1; i<=3; i++) {
        const el = document.getElementById(`step${i}_ind`);
        el.classList.remove('active', 'completed');
        if(i < step) el.classList.add('completed');
        if(i === step) el.classList.add('active');
    }
}

function prevStep(step) {
    nextStep(step);
}

async function submitProRequest() {
    if(!document.getElementById('auth_check').checked) return alert("Please authorize the request.");
    
    const btn = document.querySelector('#step3 button.btn-success');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing...';

    const formData = new FormData();
    formData.append("username", currentUser.username);
    formData.append("scan_type", document.getElementById('req_type').value);
    
    // Combine inputs into description for fuller context
    const desc = `
    Project: ${document.getElementById('req_title').value}
    Env: ${document.querySelector('input[name="env"]:checked').value}
    POC: ${document.getElementById('req_poc_name').value} (${document.getElementById('req_poc_email').value})
    Notes: ${document.getElementById('req_desc').value}
    `;
    
    formData.append("target", document.getElementById('req_target').value);
    formData.append("description", desc.trim());
    formData.append("priority", document.getElementById('req_priority').value);
    
    const file = document.getElementById('req_file').files[0];
    if (file) formData.append("file", file);

    try {
        const res = await fetch('/submit-request', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}` },
            body: formData
        });
        
        const d = await res.json();
        if(d.success) {
            alert("Request Submitted Successfully! Reference ID generated.");
            // Reset Form
            document.getElementById('proRequestForm').reset();
            nextStep(1); // Back to start
            showSection('my_requests');
        } else {
            alert("Error: " + d.detail);
        }
    } catch(e) {
        alert("Submission Failed.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = 'Submit Request <i class="fas fa-check ms-2"></i>';
    }
}

function loadRequests() {
    fetch(`/user/my-requests?username=${currentUser.username}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
    }).then(r => r.json()).then(data => {
        const tbody = document.getElementById('requests_table_body');
        if(data.requests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center py-5 text-muted">No requests found. Start a new assessment!</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        if(data.requests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center py-5 text-muted">No requests found. Start a new assessment!</td></tr>';
            return;
        }

        data.requests.forEach(req => {
            const tr = document.createElement('tr');
            
            // Ref ID
            const tdId = document.createElement('td');
            tdId.className = 'ps-4 fw-bold font-monospace text-secondary';
            tdId.textContent = `REF-${req.id}`;
            tr.appendChild(tdId);

            // Target (XSS Protection)
            const tdTarget = document.createElement('td');
            tdTarget.className = 'fw-bold text-dark';
            tdTarget.textContent = req.target;
            tr.appendChild(tdTarget);

            // Type (XSS Protection)
            const tdType = document.createElement('td');
            tdType.textContent = req.scan_type;
            tr.appendChild(tdType);

            // Date
            const tdDate = document.createElement('td');
            tdDate.className = 'text-muted small';
            tdDate.textContent = new Date(req.timestamp).toLocaleDateString();
            tr.appendChild(tdDate);

            // Status Badge
            const tdStatus = document.createElement('td');
            let statusBadge = document.createElement('span');
            statusBadge.className = 'badge bg-secondary';
            statusBadge.textContent = 'Pending';
            
            if(req.status === 'Approved' || req.status === 'Processing') {
                statusBadge.className = 'badge bg-info text-dark';
                statusBadge.textContent = 'Processing';
            }
            if(req.status === 'Completed') {
                statusBadge.className = 'badge bg-success';
                statusBadge.textContent = 'Completed';
            }
            if(req.status === 'Review Pending') {
                statusBadge.className = 'badge bg-warning text-dark';
                statusBadge.textContent = 'Reviewing';
            }
            if(req.status === 'Scanning Ports...' || req.status === 'Scanning...') {
                statusBadge.className = 'badge bg-info text-dark';
                statusBadge.innerHTML = '<span class="spinner-grow spinner-grow-sm me-1" style="width:0.5rem;height:0.5rem;"></span>Scanning';
            }
            tdStatus.appendChild(statusBadge);
            tr.appendChild(tdStatus);

            // Report Button
            const tdReport = document.createElement('td');
            if(req.status === 'Completed' && req.report_filename) {
                const a = document.createElement('a');
                a.href = `/download-report/${req.report_filename}?token=${authToken}`;
                a.className = 'btn btn-sm btn-outline-primary';
                a.target = '_blank';
                a.innerHTML = '<i class="fas fa-download me-1"></i> Report';
                tdReport.appendChild(a);
            } else {
                const span = document.createElement('span');
                span.className = 'text-muted small';
                span.textContent = 'Not Ready';
                tdReport.appendChild(span);
            }
            tr.appendChild(tdReport);

            tbody.appendChild(tr);
        });
    });
}

function loadUserDashboardStats() {
    if(!currentUser) return;
    
    // Set Welcome Name
    const nameEl = document.getElementById('dash_user_name');
    if(nameEl) nameEl.innerText = currentUser.name.split(' ')[0]; // First Name

    fetch(`/user/my-requests?username=${currentUser.username}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
    }).then(r => r.json()).then(data => {
        const reqs = data.requests;
        
        // Calculate Stats
        const active = reqs.filter(r => ['Approved', 'Processing', 'Pending', 'Scanning Ports...'].includes(r.status)).length;
        const action = reqs.filter(r => r.status === 'Review Pending').length;
        const completed = reqs.filter(r => r.status === 'Completed').length;
        
        document.getElementById('stat_active').innerText = active;
        document.getElementById('stat_action').innerText = action;
        document.getElementById('stat_completed').innerText = completed;
        
        // Populate Recent Activity Table
        const recentBody = document.getElementById('dash_recent_table');
        recentBody.innerHTML = '';
        
        if(reqs.length === 0) {
            recentBody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-muted">No activity yet.</td></tr>';
        } else {
            // Top 5 recent
            reqs.slice(0, 5).forEach(req => {
                const tr = document.createElement('tr');

                // Target (XSS Protection)
                const tdTarget = document.createElement('td');
                tdTarget.className = 'ps-4 fw-bold text-dark';
                tdTarget.textContent = req.target;
                tr.appendChild(tdTarget);

                // Type (XSS Protection)
                const tdType = document.createElement('td');
                tdType.className = 'small text-muted';
                tdType.textContent = req.scan_type;
                tr.appendChild(tdType);

                // Status
                const tdStatus = document.createElement('td');
                tdStatus.className = 'small text-secondary';
                if(req.status === 'Completed') tdStatus.className = 'small text-success fw-bold';
                if(req.status === 'Processing' || req.status === 'Approved') tdStatus.className = 'small text-primary fw-bold';
                if(req.status === 'Review Pending') tdStatus.className = 'small text-warning fw-bold';
                tdStatus.textContent = req.status;
                tr.appendChild(tdStatus);

                // Date
                const tdDate = document.createElement('td');
                tdDate.className = 'text-muted small';
                tdDate.textContent = new Date(req.timestamp).toLocaleDateString();
                tr.appendChild(tdDate);

                recentBody.appendChild(tr);
            });
        }
    });
}

function loadProfileData() {
    document.getElementById('req_dept').value = currentUser.department || "N/A";
    document.getElementById('req_poc_email').value = currentUser.email || "";
    
    // Profile Page
    document.getElementById('p_name').innerText = currentUser.name;
    document.getElementById('p_desig').innerText = currentUser.designation;
    document.getElementById('p_dept').innerText = currentUser.department;
    document.getElementById('p_email').innerText = currentUser.email;
    document.getElementById('p_empid').innerText = currentUser.employee_id;
    document.getElementById('p_phone').innerText = currentUser.phone;
    
    if(currentUser.employee_id && currentUser.employee_id !== 'N/A') {
        const url = `https://photos.iitm.ac.in/byid.php?id=${currentUser.employee_id}`;
        const img = document.getElementById('p_img');
        img.src = url;
        img.onerror = () => { img.src = '/static/img/default_user.png'; }
    }
}
