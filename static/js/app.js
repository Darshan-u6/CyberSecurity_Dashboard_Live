// Global State
let currentUser = null;
let currentSection = 'dashboard';
let authToken = null;

// Init
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    if(authToken) {
        showSection('dashboard');
        updateDashboardStats();
        initDashboard();
        startClock();
    }
});

function startClock() {
    function update() {
        const now = new Date();
        const el = document.getElementById('clock');
        if(el) el.innerText = now.toLocaleTimeString('en-GB', { hour12: false }) + " UTC+5:30";
    }
    update();
    setInterval(update, 1000);
}

// Authentication
function checkAuth() {
    authToken = localStorage.getItem('iitm_admin_token');
    const userStr = localStorage.getItem('iitm_admin_user');
    
    if (!authToken || !userStr) {
        window.location.href = '/static/admin_login.html';
        return;
    }
    
    currentUser = JSON.parse(userStr);
    
    // Admin Check
    if (currentUser.role !== 'admin') {
        alert("Access Denied. Admins Only.");
        localStorage.removeItem('iitm_admin_token');
        localStorage.removeItem('iitm_admin_user');
        window.location.href = '/static/user_dashboard.html';
        return;
    }
    
    const userDisplay = document.getElementById('userDisplay');
    if(userDisplay) userDisplay.innerText = currentUser.name || currentUser.username;
}

function logout() {
    localStorage.removeItem('iitm_admin_token');
    localStorage.removeItem('iitm_admin_user');
    window.location.href = '/static/admin_login.html';
}

// Secure Fetch Wrapper
async function secureFetch(url, options = {}) {
    if (!options.headers) options.headers = {};
    options.headers['Authorization'] = `Bearer ${authToken}`;
    
    const response = await fetch(url, options);
    
    if (response.status === 401) {
        alert("Session expired. Please login again.");
        logout();
        return null;
    }
    return response;
}

// Navigation
function showSection(sectionId) {
    currentSection = sectionId;
    document.querySelectorAll('.section').forEach(el => el.classList.add('d-none'));
    document.getElementById(sectionId).classList.remove('d-none');
    document.querySelectorAll('.sidebar a').forEach(el => el.classList.remove('active'));
    
    const link = Array.from(document.querySelectorAll('.sidebar a')).find(el => el.getAttribute('onclick')?.includes(sectionId));
    if (link) link.classList.add('active');
    
    if (window.innerWidth < 768) {
        document.getElementById('sidebar').classList.remove('active');
        document.querySelector('.main-content').style.marginLeft = '0';
    }

    if (sectionId === 'adminPanel') {
        loadAdminRequests();
        startAdminRequestsPolling();
    } else {
        stopAdminRequestsPolling();
    }
    if (sectionId === 'compliance') loadComplianceOverview();
}

let adminRequestsInterval = null;
function startAdminRequestsPolling() {
    if(adminRequestsInterval) clearInterval(adminRequestsInterval);
    adminRequestsInterval = setInterval(loadAdminRequests, 5000);
}

function stopAdminRequestsPolling() {
    if(adminRequestsInterval) clearInterval(adminRequestsInterval);
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('active');
}

function loadProfile() {
    if(!currentUser) return;
    
    // Photo Logic
    let photoUrl = '/static/img/default_user.png';
    if(currentUser.employee_id && currentUser.employee_id !== "N/A") {
        photoUrl = `https://photos.iitm.ac.in/byid.php?id=${currentUser.employee_id}`;
    }

    // User Profile View
    if(document.getElementById('p_name')) {
        document.getElementById('p_name').innerText = currentUser.name;
        document.getElementById('p_email').innerText = currentUser.email;
        document.getElementById('p_dept').innerText = currentUser.department;
        document.getElementById('p_desig').innerText = currentUser.designation;
        
        // Expanded Details
        if(document.getElementById('p_full_name')) document.getElementById('p_full_name').innerText = currentUser.name;
        if(document.getElementById('p_full_desig')) document.getElementById('p_full_desig').innerText = currentUser.designation;

        document.getElementById('p_role').innerText = currentUser.role;
        document.getElementById('p_empid').innerText = currentUser.employee_id;
        document.getElementById('p_phone').innerText = currentUser.phone || "N/A";
        
        // Photo
        const pPhoto = document.getElementById('p_photo');
        pPhoto.src = photoUrl;
        pPhoto.onerror = function() { this.src = '/static/img/default_user.png'; };
    }
    
    // Admin Panel Profile View
    if(document.getElementById('ap_name')) {
        document.getElementById('ap_name').innerText = currentUser.name;
        document.getElementById('ap_email').innerText = currentUser.email;
        document.getElementById('ap_role').innerText = currentUser.role;
        document.getElementById('ap_dept').innerText = currentUser.department;
        document.getElementById('ap_empid').innerText = currentUser.employee_id;
        
        if(document.getElementById('ap_full_name')) document.getElementById('ap_full_name').innerText = currentUser.name;
        if(document.getElementById('ap_full_desig')) document.getElementById('ap_full_desig').innerText = currentUser.designation;

        // Photo
        const apPhoto = document.getElementById('ap_photo');
        apPhoto.src = photoUrl;
        apPhoto.onerror = function() { this.src = '/static/img/default_user.png'; };
    }
}

// --- Generic Stream Handler with UI callbacks ---
async function streamJson(url, onData, onComplete) {
    try {
        const response = await fetch(url, { headers: { 'Authorization': `Bearer ${authToken}` } });
        if (response.status === 401) { logout(); return; }
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            let lines = buffer.split('\n');
            buffer = lines.pop(); // Keep partial line
            
            for (let line of lines) {
                if (!line.trim()) continue;
                try {
                    const json = JSON.parse(line);
                    onData(json);
                } catch(e) {
                    console.warn("Non-JSON line:", line);
                }
            }
        }
        if (onComplete) onComplete();
    } catch (error) {
        console.error("Stream error:", error);
        alert("Stream Error: " + error.message);
    }
}

// --- Features ---

// Port Scan
function runPortScan() {
    const ip = document.getElementById('ps_ip').value;
    const ports = document.getElementById('ps_ports').value;
    if (!ip) return alert("Enter IP");
    
    const tbody = document.getElementById('ps_table_body');
    tbody.innerHTML = "";
    document.getElementById('ps_status').innerText = "Scanning...";
    
    streamJson(`/scan?ip=${ip}&ports=${ports}`, (data) => {
        if (data.type === 'result') {
            const rowId = `ps_row_${data.data.port}`;
            const existingRow = document.getElementById(rowId);
            
            // Helper to generate service cell HTML with Icons
            const getServiceHtml = (serviceName) => {
                let icon = 'fa-server';
                // Remove ? if present (frontend safeguard)
                const cleanName = serviceName.replace(/\?/g, '');
                const svc = cleanName.toLowerCase();
                
                if (svc.includes('http')) icon = 'fa-globe';
                else if (svc.includes('ssh') || svc.includes('telnet')) icon = 'fa-terminal';
                else if (svc.includes('ftp')) icon = 'fa-folder-open';
                else if (svc.includes('sql') || svc.includes('database')) icon = 'fa-database';
                else if (svc.includes('mail') || svc.includes('smtp') || svc.includes('imap') || svc.includes('pop3')) icon = 'fa-envelope';
                else if (svc.includes('ssl') || svc.includes('https') || svc.includes('cert')) icon = 'fa-lock';
                else if (svc.includes('dns')) icon = 'fa-sitemap';
                else if (svc.includes('rdp') || svc.includes('vnc')) icon = 'fa-desktop';
                
                return `<div class="d-flex align-items-center">
                        <div class="me-3 text-secondary" style="width: 20px; text-align: center;"><i class="fas ${icon} fa-lg"></i></div>
                        <div>
                            <div class="fw-bold text-dark" style="font-family: 'Inter', sans-serif;">${cleanName}</div>
                        </div>
                    </div>`;
            };
            
            if (existingRow) {
                // Update existing row (likely with better Nmap data)
                existingRow.cells[2].innerHTML = getServiceHtml(data.data.service);
                // Add a visual highlight effect
                existingRow.classList.add('table-active');
                setTimeout(() => existingRow.classList.remove('table-active'), 1000);
            } else {
                // Create new row
                const row = `<tr id="${rowId}" class="align-middle">
                    <td><span class="fw-bold font-monospace text-info fs-6">${data.data.port}</span></td>
                    <td><span class="badge bg-success rounded-pill px-3"><i class="fas fa-check-circle me-1"></i>OPEN</span></td>
                    <td>${getServiceHtml(data.data.service)}</td>
                </tr>`;
                tbody.innerHTML += row;
            }
        } else if (data.type === 'status') {
            document.getElementById('ps_status').innerText = data.message;
        } else if (data.type === 'success') {
             const btn = document.getElementById('ps_download_btn');
             btn.classList.remove('d-none');
             btn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
             document.getElementById('ps_status').innerText = data.message;
        }
    });
}

function loadComplianceOverview() {
    const container = document.getElementById('comp_dashboard_area');
    if(container) container.innerHTML = '';
}

// IP Range
function runIPRangeScan() {
    const range = document.getElementById('ir_range').value;
    if (!range) return alert("Enter Range");
    const tbody = document.getElementById('ir_table_body');
    tbody.innerHTML = "";
    document.getElementById('ir_status').innerText = "Scanning...";
    
    streamJson(`/scan-range-stream?range_str=${range}`, (data) => {
        if (data.type === 'result') {
             // Create unique ID for row based on IP
             const rowId = `ir_row_${data.data.ip.replace(/\./g, '_')}`;
             let row = document.getElementById(rowId);
             
             // Dynamic Badge Color
             let badgeClass = 'bg-secondary';
             if (data.data.status === 'Active') badgeClass = 'bg-success';
             else if (data.data.status === 'Inactive') badgeClass = 'bg-danger';
             else if (data.data.status === 'Scanning...') badgeClass = 'bg-warning text-dark';
             
             const rowContent = `
                <td>${data.data.ip}</td>
                <td><span class="badge ${badgeClass}">${data.data.status}</span></td>
                <td>${data.data.hostname_details || '-'}</td>
             `;
             
             if (row) {
                 row.innerHTML = rowContent;
                 // Highlight update if status changed to Active/Inactive
                 if (data.data.status === 'Active' || data.data.status === 'Inactive') {
                    row.classList.add('table-active');
                    setTimeout(() => row.classList.remove('table-active'), 1000);
                 }
             } else {
                 row = document.createElement('tr');
                 row.id = rowId;
                 row.innerHTML = rowContent;
                 tbody.appendChild(row);
             }

        } else if (data.type === 'info') {
             document.getElementById('ir_status').innerText = data.message;
        } else if (data.type === 'success') {
             const btn = document.getElementById('ir_download_btn');
             btn.classList.remove('d-none');
             btn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
        }
    });
}

// Network Monitor
function runZoneScan(zoneName, range) {
    document.getElementById('nm_range').value = range;
    document.getElementById('nm_scan_title').innerText = `Active Monitoring: ${zoneName}`;
    runNetworkMonitor();
}

// SOC Network Monitor Logic
let nm_stats = { total: 0, critical: 0, secure: 0 };

function runNetworkMonitor() {
    const range = document.getElementById('nm_range').value;
    const tbody = document.getElementById('nm_table_body');
    
    // Reset Stats
    nm_stats = { total: 0, critical: 0, secure: 0 };
    updateSOCStats();
    
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-warning py-5"><div class="spinner-border text-warning mb-3"></div><br>Initializing Advanced SOC Scan on ' + range + '...</td></tr>';
    
    const url = range ? `/network-monitor?range_str=${range}` : `/network-monitor`;
    let found = false;
    
    streamJson(url, (data) => {
        if (!found && data.type === 'result') {
            tbody.innerHTML = "";
            found = true;
        }
        
        if (data.type === 'result' && data.data.status === 'active') {
             nm_stats.total++;
             
             const d = data.data;
             let riskBadge = '<span class="badge bg-success">SECURE</span>';
             let trClass = "";
             
             if (d.risk === 'CRITICAL') {
                 riskBadge = '<span class="badge bg-danger pulse">CRITICAL THREAT</span>';
                 trClass = "border-start border-5 border-danger bg-danger bg-opacity-10";
                 nm_stats.critical++;
             } else if (d.risk === 'High') {
                 riskBadge = '<span class="badge bg-warning text-dark">HIGH RISK</span>';
                 trClass = "border-start border-5 border-warning";
                 nm_stats.critical += 0.5; // Weight half
             } else if (d.risk === 'Medium') {
                 riskBadge = '<span class="badge bg-info text-dark">ELEVATED</span>';
             } else {
                 nm_stats.secure++;
             }
             
             const safeIp = d.ip.replace(/\./g, '_');
             const rowId = `nm_row_${safeIp}`;
             
             // Device Icon
             let devIcon = '<i class="fas fa-desktop text-muted"></i>';
             if (d.device_type.includes("Server")) devIcon = '<i class="fas fa-server text-warning"></i>';
             else if (d.device_type.includes("Database")) devIcon = '<i class="fas fa-database text-info"></i>';
             else if (d.device_type.includes("Legacy")) devIcon = '<i class="fas fa-network-wired text-danger"></i>';
             
             // Threat Tags
             let threatHtml = '<span class="text-muted small italic">No active threats detected.</span>';
             if (d.threats && d.threats.length > 0) {
                 threatHtml = d.threats.map(t => 
                    `<div class="d-flex align-items-center text-danger small mb-1"><i class="fas fa-exclamation-triangle me-2"></i>${t}</div>`
                 ).join('');
             }
             
             // Score Bar (Security Score: Higher is better)
             let scoreColor = 'danger';
             if(d.score >= 80) scoreColor = 'success';
             else if(d.score >= 50) scoreColor = 'warning';
             
             const riskBar = `
                <div class="d-flex align-items-center">
                    <span class="me-2 fw-bold text-${scoreColor}">${d.score}/100</span>
                    <div class="progress flex-grow-1" style="height: 4px;">
                        <div class="progress-bar bg-${scoreColor}" style="width: ${d.score}%"></div>
                    </div>
                </div>
             `;

             const rowContent = `
                <td class="ps-4">
                    <div class="d-flex align-items-center">
                        <div class="me-3 p-2 bg-dark rounded border border-secondary">${devIcon}</div>
                        <div>
                            <div class="text-dark fw-bold font-monospace">${d.ip}</div>
                            <small class="text-muted">${d.device_type}</small>
                        </div>
                    </div>
                </td>
                <td><span class="badge bg-success rounded-pill"><i class="fas fa-wifi me-1"></i>ONLINE</span></td>
                <td>
                    <div class="fw-bold text-dark mb-1">${riskBadge}</div>
                    ${scoreColor === 'danger' ? '<small class="text-danger">Action Required</small>' : ''}
                </td>
                <td>${threatHtml}</td>
                <td class="pe-4">${riskBar}</td>
             `;
             
             let row = document.getElementById(rowId);
             if (row) {
                 row.innerHTML = rowContent;
                 row.className = `align-middle ${trClass}`;
             } else {
                 row = document.createElement('tr');
                 row.id = rowId;
                 row.className = `align-middle ${trClass}`;
                 row.innerHTML = rowContent;
                 tbody.appendChild(row);
             }
             
             updateSOCStats();
             
        }
        if (data.type === 'success') {
             const btn = document.getElementById('nm_download_btn');
             btn.classList.remove('d-none');
             btn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
        }

    }, () => {
        if (!found) tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-5">No active hosts found in this sector.</td></tr>';
    });
}

function updateSOCStats() {
    document.getElementById('nm_stats_total').innerText = nm_stats.total;
    document.getElementById('nm_stats_critical').innerText = Math.ceil(nm_stats.critical);
    
    let health = 100;
    if (nm_stats.total > 0) {
        // Simple health calc
        health = Math.max(0, 100 - ((nm_stats.critical / nm_stats.total) * 100));
    }
    document.getElementById('nm_stats_health').innerText = Math.round(health) + "%";
    
    // Colorize Health
    const hEl = document.getElementById('nm_stats_health');
    if(health < 50) hEl.className = "mb-0 text-danger fw-bold";
    else if(health < 80) hEl.className = "mb-0 text-warning fw-bold";
    else hEl.className = "mb-0 text-success fw-bold";
}

// Compliance
function runCompliance() {
    const target = document.getElementById('comp_target').value;
    if (!target) return alert("Enter Target Host");
    
    const container = document.getElementById('comp_results_container');
    const dashboard = document.getElementById('comp_dashboard_area');
    
    // Initial UI State
    document.getElementById('comp_status').innerHTML = '<span class="text-primary spinner-border spinner-border-sm me-2"></span>Initiating Audit...';
    
    // Setup Dashboard Area
    dashboard.innerHTML = `
        <div class="card bg-white shadow-sm border-0 mb-4">
            <div class="card-body py-4">
                <div class="row align-items-center">
                    <div class="col-md-4 text-center border-end">
                        <h6 class="text-muted text-uppercase small ls-1">Audit Status</h6>
                        <h4 class="text-primary fw-bold mb-0">RUNNING</h4>
                    </div>
                    <div class="col-md-4 text-center border-end">
                        <h6 class="text-muted text-uppercase small ls-1">Checks Passed</h6>
                        <h4 class="text-success fw-bold mb-0" id="comp_pass_count">0</h4>
                    </div>
                    <div class="col-md-4 text-center">
                        <h6 class="text-muted text-uppercase small ls-1">Real-time Score</h6>
                        <h4 class="text-dark fw-bold mb-0" id="comp_live_score">Calculating...</h4>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Reset Results Grid
    container.innerHTML = `
        <div class="row g-3" id="comp_cards_grid">
            <!-- Dynamic Cards -->
        </div>
    `;
    const grid = document.getElementById('comp_cards_grid');
    
    let totalChecks = 0;
    let passedChecks = 0;
    
    streamJson(`/compliance-check?target=${target}`, (data) => {
        if (data.type === 'check') {
            totalChecks++;
            if (data.status === 'PASS') passedChecks++;
            
            // Determine Styling
            let borderClass = 'border-start border-4 border-success';
            let icon = 'fa-check-circle text-success';
            let bgClass = 'bg-white';
            let badgeClass = 'bg-success';
            
            if (data.status === 'FAIL') {
                borderClass = 'border-start border-4 border-danger';
                icon = 'fa-times-circle text-danger';
                bgClass = 'bg-danger bg-opacity-10';
                badgeClass = 'bg-danger';
            } else if (data.status === 'WARN') {
                borderClass = 'border-start border-4 border-warning';
                icon = 'fa-exclamation-triangle text-warning';
                badgeClass = 'bg-warning text-dark';
            } else if (data.status === 'INFO') {
                borderClass = 'border-start border-4 border-info';
                icon = 'fa-info-circle text-info';
                badgeClass = 'bg-info text-dark';
            }
            
            const card = `
            <div class="col-md-6 col-xl-4">
                <div class="card shadow-sm h-100 ${borderClass} ${bgClass}">
                    <div class="card-body py-3">
                        <div class="d-flex justify-content-between align-items-start">
                            <div class="d-flex align-items-center">
                                <div class="me-3"><i class="fas ${icon} fa-lg"></i></div>
                                <div>
                                    <div class="small text-muted fw-bold text-uppercase" style="font-size:0.7rem;">${data.category}</div>
                                    <h6 class="fw-bold mb-1 text-dark text-truncate" style="max-width: 200px;" title="${data.title}">${data.title}</h6>
                                    <p class="mb-0 small text-secondary text-truncate" style="max-width: 250px;" title="${data.details}">${data.details}</p>
                                </div>
                            </div>
                            <span class="badge ${badgeClass}">${data.status}</span>
                        </div>
                    </div>
                </div>
            </div>`;
            
            grid.insertAdjacentHTML('beforeend', card);
            
            // Update Dashboard Stats
            document.getElementById('comp_pass_count').innerText = passedChecks + "/" + totalChecks;
            const liveScore = Math.round((passedChecks / totalChecks) * 100);
            document.getElementById('comp_live_score').innerText = liveScore + "%";
            
        } else if (data.type === 'section') {
             grid.insertAdjacentHTML('beforeend', `<div class="col-12 mt-4"><h6 class="text-dark fw-bold border-bottom pb-2"><i class="fas fa-layer-group text-primary me-2"></i>${data.title}</h6></div>`);
        } else if (data.type === 'status') {
             const statusEl = document.getElementById('comp_status');
             if(data.message.includes("Querying")) {
                 statusEl.innerHTML = `<span class="text-info fw-bold"><i class="fas fa-database me-2"></i>${data.message}</span>`;
             } else {
                 statusEl.innerHTML = data.message;
             }
        } else if (data.type === 'score') {
             // Final Score Visual
             const score = data.score;
             const color = score >= 80 ? 'success' : (score >= 50 ? 'warning' : 'danger');
             dashboard.innerHTML = `
                <div class="card bg-white shadow-sm border-0 mb-4">
                    <div class="card-body py-4 text-center">
                        <h5 class="mb-3 text-dark fw-bold">IIT Madras Compliance Audit Result</h5>
                        <div style="width: 150px; height: 150px; border-radius: 50%; background: conic-gradient(var(--bs-${color}) ${score}%, #f0f0f0 0); margin: 0 auto; display: flex; align-items: center; justify-content: center;">
                            <div style="width: 130px; height: 130px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column;">
                                <h1 class="mb-0 fw-bold text-${color}">${score}</h1>
                                <small class="text-muted fw-bold">SCORE</small>
                            </div>
                        </div>
                        <div class="mt-3">
                            <span class="badge bg-${color} px-3 py-2 rounded-pill">AUDIT COMPLETE</span>
                        </div>
                    </div>
                </div>
             `;
        } else if (data.type === 'success') {
             const btn = document.getElementById('comp_download_btn');
             btn.classList.remove('d-none');
             btn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
             document.getElementById('comp_status').innerHTML = '<span class="text-success fw-bold"><i class="fas fa-check-circle me-1"></i>Completed</span>';
        }
    });
}

function updateComplianceScore(passed, total, target) {
    // Deprecated by new inline logic, but kept for safety if referenced elsewhere
}

// VAPT
function runVAPT() {
    const target = document.getElementById('vapt_target').value;
    if (!target) return alert("Enter Target");
    
    const container = document.getElementById('vapt_results_container');
    
    // Initial UI State
    container.innerHTML = `
        <div class="d-flex align-items-center mb-4 pb-2 border-bottom">
            <div class="bg-primary bg-opacity-10 p-2 rounded-circle me-3 text-primary">
                <i class="fas fa-shield-alt fa-2x"></i>
            </div>
            <div>
                <h5 class="mb-0 fw-bold text-dark">Real-time VAPT Analysis</h5>
                <small class="text-muted">Comprehensive Vulnerability Assessment & Penetration Testing</small>
            </div>
            <div class="ms-auto">
                <div class="spinner-border text-primary spinner-border-sm" role="status"></div>
                <span class="small text-muted ms-2">Scanning in progress...</span>
            </div>
        </div>
        <div class="row g-3" id="vapt_cards_grid"></div>
    `;
    
    const grid = document.getElementById('vapt_cards_grid');
    document.getElementById('vapt_ui').style.display = 'block';
    document.getElementById('vapt_status').innerText = "Starting VAPT...";
    const btn = document.getElementById('vapt_download_btn');
    btn.classList.add('disabled');
    
    streamJson(`/vapt-scan?target=${target}`, (data) => {
        if (data.type === 'finding') {
            if (data.message) {
                data.message = data.message.replace(/</g, '&lt;').replace(/>/g, '&gt;');
            }
            let borderClass = 'border-start border-4 border-info';
            let bgClass = 'bg-white';
            let badgeClass = 'bg-info text-dark';
            let icon = 'fa-info-circle text-info';
            
            if (data.severity === 'Critical') {
                borderClass = 'border-start border-4 border-danger';
                bgClass = 'bg-danger bg-opacity-10';
                badgeClass = 'bg-danger';
                icon = 'fa-radiation text-danger';
            } else if (data.severity === 'High') {
                borderClass = 'border-start border-4 border-danger';
                badgeClass = 'bg-danger';
                icon = 'fa-exclamation-triangle text-danger';
            } else if (data.severity === 'Medium') {
                borderClass = 'border-start border-4 border-warning';
                badgeClass = 'bg-warning text-dark';
                icon = 'fa-bug text-warning';
            } else if (data.severity === 'Low') {
                borderClass = 'border-start border-4 border-success';
                badgeClass = 'bg-success';
                icon = 'fa-check text-success';
            }

            const time = new Date().toLocaleTimeString();
            
            // Clean up message for display
            let message = data.message;
            if (message.length > 300) message = message.substring(0, 300) + '...';

            const card = `
            <div class="col-12">
                <div class="card shadow-sm ${borderClass} ${bgClass}">
                    <div class="card-body py-3">
                        <div class="d-flex justify-content-between align-items-start">
                            <div class="d-flex align-items-start">
                                <div class="me-3 mt-1"><i class="fas ${icon} fa-lg"></i></div>
                                <div>
                                    <div class="d-flex align-items-center mb-1">
                                        <span class="badge bg-light text-dark border me-2">${data.tool}</span>
                                        <span class="badge ${badgeClass} me-2">${data.severity.toUpperCase()}</span>
                                        <small class="text-muted">${time}</small>
                                    </div>
                                    <p class="mb-0 font-monospace small text-dark">${message}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>`;
            
            grid.insertAdjacentHTML('beforeend', card);
            
            // Auto scroll container
            container.scrollTop = container.scrollHeight;
            
        } else if (data.type === 'status' || data.type === 'info') {
             document.getElementById('vapt_status').innerText = data.message;
             
             if(data.message.includes("Running")) {
                 grid.insertAdjacentHTML('beforeend', `<div class="col-12 text-center my-2"><small class="text-muted fw-bold text-uppercase border-bottom pb-1">${data.message}</small></div>`);
                 container.scrollTop = container.scrollHeight;
             }

        } else if (data.type === 'section') {
             grid.insertAdjacentHTML('beforeend', `<div class="col-12 mt-4"><h6 class="text-dark fw-bold border-bottom pb-2"><i class="fas fa-search text-primary me-2"></i>${data.title}</h6></div>`);
             container.scrollTop = container.scrollHeight;
             
        } else if (data.type === 'success') {
             // Enable download
             btn.onclick = (e) => { e.preventDefault(); downloadFile(`/download-report/${data.report_filename}`); };
             btn.classList.remove('disabled');
             document.getElementById('vapt_status').innerHTML = '<span class="text-success"><i class="fas fa-check-circle me-1"></i> Scan Complete</span>';
             
             // Update Spinner
             const spinner = container.querySelector('.spinner-border');
             if(spinner) {
                 spinner.parentElement.innerHTML = '<span class="badge bg-success">COMPLETED</span>';
             }
        } else if (data.type === 'warning') {
             grid.insertAdjacentHTML('beforeend', `<div class="col-12"><div class="alert alert-warning py-2 mb-0 small"><i class="fas fa-exclamation-triangle me-2"></i>${data.message}</div></div>`);
        } else if (data.type === 'error') {
             grid.insertAdjacentHTML('beforeend', `<div class="col-12"><div class="alert alert-danger py-2 mb-0 small"><i class="fas fa-times-circle me-2"></i>${data.message}</div></div>`);
        }
    }, () => {
         console.log("VAPT Stream Ended");
    });
}

async function downloadFile(url) {
    const res = await secureFetch(url);
    if(res) {
        const blob = await res.blob();
        const link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        
        let filename = null;
        const disposition = res.headers.get('Content-Disposition');
        if (disposition && disposition.indexOf('attachment') !== -1) {
            const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
            const matches = filenameRegex.exec(disposition);
            if (matches != null && matches[1]) { 
                filename = matches[1].replace(/['"]/g, '');
            }
        }
        
        if (!filename) {
            filename = url.split('/').pop().split('?')[0];
        }
        
        // Ensure PDF extension for reports if missing
        if (!filename.toLowerCase().endsWith('.pdf') && 
           (url.includes('report') || url.includes('pdf') || url.includes('scan') || url.includes('vapt'))) {
            filename += '.pdf';
        }
        
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(link.href);
    }
}

// Virus Scan
function runVirusScan() {
    const target = document.getElementById('vs_target').value;
    if (!target) return alert("Enter target");
    
    // UI Elements
    const container = document.getElementById('vs_results_container');
    const board = document.getElementById('vs_status_board');
    const spinner = document.getElementById('vs_spinner');
    const statusText = document.getElementById('vs_status_text');
    const threatCountEl = document.getElementById('vs_threat_count');
    const sigCountEl = document.getElementById('vs_sig_count');
    const dlBtn = document.getElementById('vs_download_btn');
    
    // Reset UI
    container.innerHTML = `<div class="row g-3" id="vs_grid"></div>`;
    const grid = document.getElementById('vs_grid');
    board.classList.remove('d-none');
    dlBtn.classList.add('d-none');
    spinner.classList.remove('d-none');
    statusText.innerText = "Initializing Threat Engine...";
    threatCountEl.innerText = "0";
    sigCountEl.innerText = "0";
    
    let threats = 0;
    let sigs = 0;

    streamJson(`/virus-scan?target=${target}`, (data) => {
        if (data.type === 'status') {
             statusText.innerText = data.message;
        } 
        else if (data.type === 'signature_check') {
            sigs++;
            sigCountEl.innerText = sigs;
            const d = data.data;
            
            // Only show detected or interesting items to avoid spamming 50+ green boxes
            if (d.status === 'Detected') {
                threats++;
                threatCountEl.innerText = threats;
                
                const card = `
                <div class="col-md-6 col-lg-4 fade-in-up">
                    <div class="card shadow-sm border-start border-4 border-danger h-100 bg-white">
                        <div class="card-body">
                            <div class="d-flex justify-content-between">
                                <div class="d-flex align-items-center mb-2">
                                    <i class="fas fa-biohazard text-danger fa-2x me-3"></i>
                                    <div>
                                        <h6 class="fw-bold text-dark mb-0">${d.name}</h6>
                                        <small class="text-danger fw-bold">THREAT DETECTED</small>
                                    </div>
                                </div>
                                <span class="badge bg-danger align-self-start">${d.severity}</span>
                            </div>
                            <div class="mt-2 small text-muted font-monospace bg-light p-2 rounded">
                                Sig ID: ${d.id}<br>Type: ${d.type}
                            </div>
                        </div>
                    </div>
                </div>`;
                grid.insertAdjacentHTML('afterbegin', card);
            }
        } 
        else if (data.type === 'alert' || (data.type === 'result' && data.data && data.data.severity === 'Critical')) {
            threats++;
            threatCountEl.innerText = threats;
            
            const msg = data.message || (data.data ? data.data.message : "Unknown Alert");
            const alertCard = `
            <div class="col-12 fade-in-up">
                <div class="alert alert-danger border-danger border-start border-4 shadow-sm">
                    <div class="d-flex">
                        <i class="fas fa-exclamation-circle fa-2x me-3"></i>
                        <div>
                            <h6 class="fw-bold mb-1">Heuristic Alert</h6>
                            <p class="mb-0 small">${msg}</p>
                        </div>
                    </div>
                </div>
            </div>`;
            grid.insertAdjacentHTML('afterbegin', alertCard);
        }
        else if (data.type === 'success') {
             if (data.report_filename) {
                 dlBtn.classList.remove('d-none');
                 dlBtn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
             }
             
             statusText.innerText = "Scan Complete";
             spinner.classList.add('d-none');
             statusText.classList.replace('text-primary', 'text-success');
             
             if (threats === 0) {
                 grid.innerHTML = `
                 <div class="col-12 text-center py-5 fade-in-up">
                    <div class="mb-3 text-success"><i class="fas fa-shield-virus fa-4x"></i></div>
                    <h4 class="text-success fw-bold">System Clean</h4>
                    <p class="text-muted">No active threats or malicious signatures detected on target.</p>
                 </div>` + grid.innerHTML;
             }
        }
    });
}

// CVE Scan (IIT Madras Advanced)
function runCVEScan() {
    const target = document.getElementById('cve_target').value;
    if (!target) return alert("Enter target");
    
    // Switch to Card Layout container logic
    const container = document.getElementById('cve_results_container');
    
    // Stats State
    let cveStats = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    let totalVulns = 0;
    
    container.innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="mt-2 text-muted">Initializing IIT Madras Advanced Vulnerability Analysis...</p>
        </div>
    `;
    
    document.getElementById('cve_status').innerText = "Starting Analysis...";
    
    let itemsAdded = 0;
    
    streamJson(`/cve-scan?target=${target}`, (data) => {
        if (itemsAdded === 0 && (data.type === 'finding' || data.type === 'info')) {
            // Render Dashboard Header
            container.innerHTML = `
                <div class="d-flex align-items-center mb-4 pb-2 border-bottom">
                    <img src="/static/img/iitm_logo.png" width="40" class="me-3">
                    <div>
                        <h5 class="mb-0 fw-bold text-dark-blue">IIT Madras Advanced Vulnerability Analysis</h5>
                        <small class="text-muted">Real-time CVE Detection & Intelligence</small>
                    </div>
                </div>
                
                <!-- Summary Dashboard -->
                <div class="card border-0 shadow-sm mb-4 bg-light">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-3 text-center border-end">
                                <h6 class="text-muted text-uppercase small ls-1 mb-2">Total Findings</h6>
                                <h1 class="display-4 fw-bold text-dark mb-0" id="cve_total_count">0</h1>
                            </div>
                            <div class="col-md-5">
                                <div class="row g-2 text-center">
                                    <div class="col-3">
                                        <div class="p-2 rounded bg-danger text-white">
                                            <div class="small fw-bold">CRITICAL</div>
                                            <div class="h5 mb-0" id="stat_crit">0</div>
                                        </div>
                                    </div>
                                    <div class="col-3">
                                        <div class="p-2 rounded bg-warning text-dark">
                                            <div class="small fw-bold">HIGH</div>
                                            <div class="h5 mb-0" id="stat_high">0</div>
                                        </div>
                                    </div>
                                    <div class="col-3">
                                        <div class="p-2 rounded bg-info text-dark">
                                            <div class="small fw-bold">MEDIUM</div>
                                            <div class="h5 mb-0" id="stat_med">0</div>
                                        </div>
                                    </div>
                                    <div class="col-3">
                                        <div class="p-2 rounded bg-success text-white">
                                            <div class="small fw-bold">LOW</div>
                                            <div class="h5 mb-0" id="stat_low">0</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div style="height: 100px; width: 100%; position: relative;">
                                    <canvas id="cveChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row g-3" id="cve_cards_grid"></div>
            `;
            initCVEChart();
        }
        
        const grid = document.getElementById('cve_cards_grid');
        
        if (data.type === 'finding' || (data.type === 'info' && data.description)) {
            itemsAdded++;
            
            let borderClass = 'border-start border-4 border-info';
            let sev = data.severity || 'Info';
            let bgClass = 'bg-white';
            let badgeClass = 'bg-info text-dark';
            let icon = 'fa-info-circle text-info';
            
            // Update Stats
            if (cveStats[sev] !== undefined) cveStats[sev]++;
            else cveStats['Info']++;
            totalVulns++;
            
            updateCVEDashboard(cveStats, totalVulns);
            
            if (sev === 'Critical') {
                borderClass = 'border-start border-4 border-danger';
                bgClass = 'bg-danger bg-opacity-10';
                badgeClass = 'bg-danger';
                icon = 'fa-radiation text-danger';
            } else if (sev === 'High') {
                borderClass = 'border-start border-4 border-warning';
                badgeClass = 'bg-warning text-dark';
                icon = 'fa-exclamation-triangle text-warning';
            } else if (sev === 'Medium') {
                borderClass = 'border-start border-4 border-primary';
                badgeClass = 'bg-primary';
                icon = 'fa-bug text-primary';
            } else if (sev === 'Low') {
                borderClass = 'border-start border-4 border-success';
                badgeClass = 'bg-success';
                icon = 'fa-check text-success';
            }
            
            let cvssBadge = '';
            if (data.cvss > 0) {
                let cvssColor = data.cvss >= 9 ? 'danger' : (data.cvss >= 7 ? 'warning text-dark' : 'primary');
                cvssBadge = `<span class="badge bg-${cvssColor} ms-2">CVSS ${data.cvss}</span>`;
            }
            
            const card = `
                <div class="col-md-6 col-xl-4 d-flex fade-in-up">
                    <div class="card shadow-sm w-100 ${borderClass} ${bgClass}">
                        <div class="card-body d-flex flex-column">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <div class="d-flex align-items-center">
                                    <i class="fas ${icon} fa-lg me-3"></i>
                                    <div>
                                        <h6 class="fw-bold mb-0 text-dark text-truncate" style="max-width: 150px;" title="${data.cve}">${data.cve || ' vulnerability detected'}</h6>
                                        <div class="small text-muted font-monospace">${data.tool || 'Scanner'}</div>
                                    </div>
                                </div>
                                <div>
                                    <span class="badge ${badgeClass}">${sev.toUpperCase()}</span>
                                </div>
                            </div>
                            
                            ${cvssBadge ? `<div class="mb-2">${cvssBadge}</div>` : ''}
                            
                            <p class="mb-2 text-dark mt-2 small flex-grow-1">${data.description || data.message}</p>
                            
                            ${data.recommendation ? `
                                <div class="mt-3 p-2 bg-white rounded border border-light mt-auto">
                                    <small class="text-success fw-bold"><i class="fas fa-tools me-1"></i> Remediation:</small>
                                    <small class="d-block text-secondary text-truncate" title="${data.recommendation}">${data.recommendation}</small>
                                </div>
                            ` : ''}
                            
                            ${data.details ? `<small class="text-muted d-block mt-2 fst-italic text-truncate"><i class="fas fa-search me-1"></i>${data.details}</small>` : ''}
                        </div>
                    </div>
                </div>
            `;
            
            if(grid) {
                grid.insertAdjacentHTML('beforeend', card);
                // Scroll into view if needed
            }
            
        } else if (data.type === 'status') {
            document.getElementById('cve_status').innerHTML = `<div class="d-flex align-items-center"><span class="spinner-grow spinner-grow-sm text-primary me-2"></span>${data.message}</div>`;
        } else if (data.type === 'success') {
             const btn = document.getElementById('cve_download_btn');
             btn.classList.remove('d-none');
             btn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
             document.getElementById('cve_status').innerHTML = `<span class="text-success fw-bold"><i class="fas fa-check-circle me-2"></i>Analysis Complete</span>`;
             
             if (itemsAdded === 0) {
                 container.innerHTML = `
                    <div class="text-center py-5">
                        <i class="fas fa-shield-alt fa-3x text-success mb-3"></i>
                        <h5 class="text-dark">No Vulnerabilities Detected</h5>
                        <p class="text-muted">Target appears clean against IITM Advanced Database.</p>
                    </div>
                 `;
             }
        }
    }, () => {
        if (itemsAdded === 0 && !container.innerHTML.includes("No Vulnerabilities")) {
             container.innerHTML = `
                <div class="text-center py-5">
                    <i class="fas fa-question-circle fa-3x text-muted mb-3"></i>
                    <h5 class="text-dark">No Data</h5>
                    <p class="text-muted">Unable to retrieve vulnerability data. Host may be down.</p>
                </div>
             `;
        }
    });
}

// Helper for CVE Chart
let cveChartInstance = null;
function initCVEChart() {
    const ctx = document.getElementById('cveChart');
    if(!ctx) return;
    
    if(cveChartInstance) cveChartInstance.destroy();
    
    cveChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#dc3545', '#ffc107', '#0dcaf0', '#198754'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            cutout: '70%'
        }
    });
}

function updateCVEDashboard(stats, total) {
    const elTotal = document.getElementById('cve_total_count');
    if(elTotal) elTotal.innerText = total;
    
    if(document.getElementById('stat_crit')) document.getElementById('stat_crit').innerText = stats.Critical;
    if(document.getElementById('stat_high')) document.getElementById('stat_high').innerText = stats.High;
    if(document.getElementById('stat_med')) document.getElementById('stat_med').innerText = stats.Medium;
    if(document.getElementById('stat_low')) document.getElementById('stat_low').innerText = stats.Low;
    
    if(cveChartInstance) {
        cveChartInstance.data.datasets[0].data = [stats.Critical, stats.High, stats.Medium, stats.Low];
        cveChartInstance.update();
    }
}

// TLS Check
function runTLSCheck() {
    const host = document.getElementById('tls_host').value;
    if (!host) return alert("Enter host");
    
    const tbody = document.getElementById('tls_table_body');
    if(tbody) tbody.innerHTML = ""; // Clear previous
    
    const statusHeader = document.getElementById('tls_status_header');
    statusHeader.innerText = "Analyzing...";
    
    streamJson(`/check_tls?host=${host}`, (data) => {
        if (data.type === 'result') {
            if(tbody) {
                const row = `
                <tr class="align-middle">
                    <td class="fw-bold text-dark">${data.data.key}</td>
                    <td class="font-monospace text-secondary">${data.data.value}</td>
                    <td><span class="badge bg-${data.data.color} rounded-pill">${data.data.status}</span></td>
                </tr>`;
                tbody.innerHTML += row;
            }
            
            if (data.data.key === "Protocol") {
                if (data.data.color === 'success') {
                    statusHeader.innerText = "Status: SECURE";
                    statusHeader.className = "text-success fw-bold";
                } else {
                    statusHeader.innerText = "Status: INSECURE/WARNING";
                    statusHeader.className = `text-${data.data.color} fw-bold`;
                }
            }
        } else if (data.type === 'error') {
            if(tbody) tbody.innerHTML += `<tr><td colspan="3" class="text-danger">Error: ${data.message}</td></tr>`;
        } else if (data.type === 'success') {
             const btn = document.getElementById('tls_download_btn');
             btn.classList.remove('d-none');
             btn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
        }
    });
}

// Remote Logs
function fetchRemoteLogs() {
    secureFetch('/remote-logs').then(r => r.json()).then(data => {
        const tbody = document.getElementById('remote_logs_body');
        if (data.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-center">No logs received yet. Follow instructions above to connect agents.</td></tr>';
            return;
        }
        tbody.innerHTML = data.logs.map(log => `
            <tr>
                <td>${log.timestamp}</td>
                <td>${log.source}</td>
                <td><code>${log.message}</code></td>
            </tr>
        `).join('');
    });
}

function downloadAgent() {
    downloadFile('/download-agent');
}

// Bulk Scan
function runBulkScan() {
    const fileInput = document.getElementById('bulk_file');
    if (!fileInput.files[0]) return alert("Select CSV");
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    const tbody = document.getElementById('bulk_table_body');
    tbody.innerHTML = "";
    
    fetch('/bulk-scan', {
        method: 'POST', 
        body: formData,
        headers: { 'Authorization': `Bearer ${authToken}` }
    }).then(async res => {
        if(res.status===401) { logout(); return; }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
         while(true) {
            const {value, done} = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, {stream: true});
             let lines = buffer.split('\n');
            buffer = lines.pop();
            for (let line of lines) {
                if(!line.trim()) continue;
                try { 
                    const data = JSON.parse(line);
                    if (data.type === 'result') {
                        tbody.innerHTML += `<tr>
                            <td>${data.data.ip}</td>
                            <td>${data.data.ports_scanned}</td>
                            <td>${data.data.open_ports.join(', ')}</td>
                            <td><span class="badge ${data.data.status === 'Online' ? 'bg-success' : 'bg-secondary'}">${data.data.status}</span></td>
                        </tr>`;
                    } else if (data.type === 'success') {
                         const btn = document.getElementById('bulk_download_btn');
                         btn.classList.remove('d-none');
                         btn.onclick = () => downloadFile(`/download-report/${data.report_filename}`);
                    }
                } catch(e) {}
            }
         }
    });
}

// Admin Logs
let allLogFiles = [];

function loadAdminLogs() {
    secureFetch('/admin/log-files').then(r => r.json()).then(data => {
        allLogFiles = data.files;
        renderLogList(allLogFiles);
        
        // Setup listeners if not already
        const searchInput = document.getElementById('log_search');
        const filterSelect = document.getElementById('log_filter');
        const dateInput = document.getElementById('log_date_filter');
        
        if(searchInput) {
            searchInput.onkeyup = () => filterLogs();
        }
        if(filterSelect) {
            filterSelect.onchange = () => filterLogs();
        }
        if(dateInput) {
            dateInput.onchange = () => filterLogs();
        }
    });
}

function filterLogs() {
    const query = document.getElementById('log_search').value.toLowerCase();
    const type = document.getElementById('log_filter').value;
    const dateVal = document.getElementById('log_date_filter') ? document.getElementById('log_date_filter').value : "";
    
    const filtered = allLogFiles.filter(f => {
        const matchesSearch = f.filename.toLowerCase().includes(query);
        const matchesType = type === 'all' || f.filename.includes(type);
        
        let matchesDate = true;
        if (dateVal) {
            // f.date is "YYYY-MM-DD HH:MM:SS"
            matchesDate = f.date.startsWith(dateVal);
        }

        return matchesSearch && matchesType && matchesDate;
    });
    
    renderLogList(filtered);
}

function renderLogList(files) {
    const tbody = document.getElementById('log_files_table_body');
    const countBadge = document.getElementById('log_count');
    if (countBadge) countBadge.innerText = files.length;
    
    if(files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-5">No logs found matching your criteria.</td></tr>';
        return;
    }
    
    tbody.innerHTML = files.map(f => {
        let icon = 'fa-file-alt text-secondary';
        let type = 'General Log';
        let badgeClass = 'bg-secondary';
        
        if (f.filename.includes('Virus')) { icon = 'fa-shield-virus text-danger'; type = 'Virus Scan'; badgeClass = 'bg-danger'; }
        else if (f.filename.includes('VAPT')) { icon = 'fa-bug text-warning'; type = 'VAPT Report'; badgeClass = 'bg-warning text-dark'; }
        else if (f.filename.includes('Compliance')) { icon = 'fa-check-circle text-success'; type = 'Compliance Audit'; badgeClass = 'bg-success'; }
        else if (f.filename.includes('Network')) { icon = 'fa-network-wired text-info'; type = 'Network Monitor'; badgeClass = 'bg-info text-dark'; }
        else if (f.filename.includes('PortScan')) { icon = 'fa-satellite-dish text-primary'; type = 'Port Scan'; badgeClass = 'bg-primary'; }
        else if (f.filename.includes('CVE')) { icon = 'fa-search-dollar text-primary'; type = 'CVE Scan'; badgeClass = 'bg-primary'; }
        
        return `
        <tr class="align-middle">
            <td class="ps-4">
                <div class="d-flex align-items-center">
                    <div class="me-3 p-2 bg-light rounded border"><i class="fas ${icon} fa-lg"></i></div>
                    <span class="fw-bold text-dark font-monospace">${f.filename}</span>
                </div>
            </td>
            <td><span class="badge ${badgeClass} rounded-pill">${type}</span></td>
            <td class="text-secondary">${f.date}</td>
            <td class="text-muted font-monospace">${(f.size/1024).toFixed(1)} KB</td>
            <td class="text-end pe-4">
                 <button class="btn btn-sm btn-outline-primary" onclick="viewLogFile('${f.filename}')"><i class="fas fa-eye me-1"></i> View</button>
            </td>
        </tr>
    `}).join('');
}

function viewLogFile(filename) {
    // Switch View
    document.getElementById('logs_list_view').classList.add('d-none');
    document.getElementById('logs_detail_view').classList.remove('d-none');

    document.getElementById('log_preview_title').innerText = filename;
    
    // Enable Download Button
    const btn = document.getElementById('dl_log_btn');
    btn.onclick = () => downloadFile(`/download-log/${filename}`);
    
    const tbody = document.getElementById('log_content_table_body');
    tbody.innerHTML = '<tr><td colspan="2" class="text-center py-5"><div class="spinner-border text-primary"></div><p class="mt-2 text-muted">Loading content...</p></td></tr>';
    
    secureFetch(`/download-log/${filename}`).then(r => r.text()).then(txt => {
        renderLogContent(txt, tbody);
    });
}

function showLogList() {
    document.getElementById('logs_list_view').classList.remove('d-none');
    document.getElementById('logs_detail_view').classList.add('d-none');
}

function renderLogContent(text, tbody) {
    const lines = text.split('\n');
    let html = '';
    
    lines.forEach((line, index) => {
        if(!line.trim() && index === lines.length - 1) return; // Skip last empty line
        
        let cssClass = '';
        let processedLine = line.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        
        // Highlight Timestamp (Simple Regex for standard formats)
        // 2024-01-01 12:00:00 or [12:00:00]
        processedLine = processedLine.replace(/^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})/, '<span class="text-secondary">$1</span>');
        
        const lower = line.toLowerCase();
        if (lower.includes('critical') || lower.includes('fail') || lower.includes('error')) {
            cssClass = 'text-danger fw-bold';
            if (lower.includes('critical')) cssClass = 'text-danger fw-bold text-decoration-underline';
        } else if (lower.includes('warn')) {
            cssClass = 'text-warning fw-bold text-dark'; // Darker warning for white bg
        } else if (lower.includes('success') || lower.includes('pass') || lower.includes('complete')) {
            cssClass = 'text-success fw-bold';
        } else if (lower.includes('info') || lower.includes('starting')) {
            cssClass = 'text-primary'; // Blue is better on white than cyan (info)
        } else if (lower.includes('debug')) {
            cssClass = 'text-secondary';
        }
        
        // Check if line looks like JSON and prettify
        if (line.trim().startsWith('{') && line.trim().endsWith('}')) {
             try {
                 const obj = JSON.parse(line);
                 processedLine = JSON.stringify(obj, null, 2).replace(/\n/g, '<br>&nbsp;&nbsp;');
             } catch(e) {}
        }

        html += `
            <tr>
                <td class="text-muted text-end border-end border-secondary" style="user-select:none;">${index + 1}</td>
                <td class="${cssClass} text-break">${processedLine}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

function copyLogContent() {
    const rows = document.getElementById('log_content_table_body').querySelectorAll('tr');
    let content = "";
    rows.forEach(row => {
        if(row.cells[1]) content += row.cells[1].innerText + "\n";
    });
    
    if(!content) return;
    navigator.clipboard.writeText(content).then(() => {
        alert("Log copied to clipboard!");
    });
}

function submitRequest() {
    const formData = new FormData();
    formData.append("username", document.getElementById('req_username').value);
    formData.append("scan_type", document.getElementById('req_type').value);
    formData.append("target", document.getElementById('req_target').value);
    formData.append("description", document.getElementById('req_desc').value);
    formData.append("priority", document.getElementById('req_priority').value);
    const file = document.getElementById('req_file').files[0];
    if (file) formData.append("file", file);
    
    fetch('/submit-request', {
        method: 'POST',
        body: formData,
        headers: { 'Authorization': `Bearer ${authToken}` }
    }).then(r => r.json()).then(d => {
        if (d.success) {
            alert("Request Submitted!");
            var modal = bootstrap.Modal.getInstance(document.getElementById('requestModal'));
            modal.hide();
            loadMyRequests();
        }
    });
}

function loadMyRequests() {
    if (!currentUser) return;
    secureFetch(`/user/my-requests?username=${currentUser.username}`).then(r => r.json()).then(data => {
         const tbody = document.getElementById('requests_table_body'); // Fixed ID based on user_dashboard.html
         if(!tbody) return; // Guard clause if running on admin page
         tbody.innerHTML = data.requests.map(req => `
            <tr>
                <td><span class="font-monospace text-secondary">#${req.id}</span></td>
                <td>
                    <div class="fw-bold text-dark">${req.target}</div>
                    <small class="text-muted">${req.scan_type}</small>
                </td>
                <td><span class="badge bg-light text-dark border">${req.scan_type}</span></td>
                <td class="text-muted small">${new Date(req.timestamp).toLocaleDateString()}</td>
                <td><span class="badge ${req.status === 'Completed' ? 'bg-success' : (req.status === 'Review Pending' ? 'bg-info' : 'bg-warning text-dark')}">${req.status}</span></td>
                <td>
                    ${(req.report_filename && req.status === 'Completed') ? 
                    `<button onclick="downloadFile('/download-report/${req.report_filename}')" class="btn btn-sm btn-outline-primary"><i class="fas fa-download me-1"></i> Download PDF</button>` : 
                    (req.status === 'Review Pending' ? '<span class="text-muted small fst-italic">Reviewing...</span>' : '<span class="text-muted small">-</span>')}
                </td>
            </tr>
         `).join('');
    });
}

function loadAdminRequests() {
     secureFetch(`/admin/requests`).then(r => r.json()).then(data => {
         const tbody = document.getElementById('admin_requests_body');
         tbody.innerHTML = data.requests.map(req => {
            let actionHtml = `<span class="badge bg-secondary">${req.status}</span>`;
            
            if (req.status === 'Pending') {
                actionHtml = `
                    <button class="btn btn-sm btn-success" onclick="approveRequest(${req.id}, 'Approved')">Approve</button>
                    <button class="btn btn-sm btn-danger" onclick="approveRequest(${req.id}, 'Rejected')">Reject</button>
                    <button class="btn btn-sm btn-outline-secondary ms-1" onclick="deleteRequest(${req.id})"><i class="fas fa-trash"></i></button>
                `;
            } else if (req.status === 'Review Pending') {
                actionHtml = `
                    <button class="btn btn-sm btn-outline-warning mb-1" onclick="downloadFile('/download-report/${req.report_filename}')"><i class="fas fa-eye"></i> Review PDF</button>
                    <br>
                    <div class="d-flex gap-1">
                        <button class="btn btn-sm btn-success flex-grow-1" onclick="handleReportAction(${req.id}, 'Release')">Release</button>
                        <button class="btn btn-sm btn-danger flex-grow-1" onclick="handleReportAction(${req.id}, 'Retry')">Re-Scan</button>
                        <button class="btn btn-sm btn-secondary flex-grow-0" onclick="deleteRequest(${req.id})" title="Delete"><i class="fas fa-trash"></i></button>
                    </div>
                `;
            } else if (req.report_filename) {
                actionHtml = `
                    <span class="badge bg-success me-2">${req.status}</span>
                    <button class="btn btn-sm btn-outline-warning" onclick="downloadFile('/download-report/${req.report_filename}')"><i class="fas fa-download"></i> PDF</button>
                    <button class="btn btn-sm btn-outline-secondary ms-1" onclick="deleteRequest(${req.id})"><i class="fas fa-trash"></i></button>
                `;
            } else {
                // Catch-all (e.g. Failed, Rejected without file)
                actionHtml = `
                    <span class="badge bg-secondary me-2">${req.status}</span>
                    <button class="btn btn-sm btn-outline-secondary" onclick="deleteRequest(${req.id})"><i class="fas fa-trash"></i></button>
                `;
            }

            return `
            <tr>
                <td>${req.id}</td>
                <td><a href="#" class="text-info text-decoration-none" onclick="showUserLDAP('${req.username}')">${req.username}</a></td>
                <td>${req.scan_type}</td>
                <td>${req.target}</td>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${req.description || ''}">${req.description || '-'}</td>
                <td><span class="badge ${req.priority === 'High' ? 'bg-danger' : (req.priority === 'Medium' ? 'bg-warning text-dark' : 'bg-success')}">${req.priority || 'Low'}</span></td>
                <td>${actionHtml}</td>
            </tr>
         `}).join('');
    });
}

function showUserLDAP(username) {
    const modal = new bootstrap.Modal(document.getElementById('ldapModal'));
    modal.show();
    const body = document.getElementById('ldap_modal_body');
    body.innerHTML = '<div class="text-center"><div class="spinner-border text-primary"></div></div>';
    
    secureFetch(`/admin/user-details/${username}`).then(r => r.json()).then(data => {
        if(data.error) {
            body.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
        } else {
            // Expanded details view
            body.innerHTML = `
                <div class="text-center mb-3">
                    <img src="https://photos.iitm.ac.in/byid.php?id=${data.employee_id}" onerror="this.src='/static/img/default_user.png'" class="rounded-circle border border-3 border-warning" style="width: 100px; height: 100px; object-fit: cover;">
                    <h5 class="mt-2 text-dark">${data.name}</h5>
                    <span class="badge bg-info text-dark">${data.designation}</span>
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item d-flex justify-content-between">
                        <span class="text-muted">Username</span> <strong class="text-dark">${data.username || username}</strong>
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <span class="text-muted">Email</span> <strong class="text-dark">${data.email}</strong>
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <span class="text-muted">Department</span> <strong class="text-end text-dark" style="max-width: 60%">${data.department}</strong>
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <span class="text-muted">Employee ID</span> <strong class="text-dark">${data.employee_id}</strong>
                    </li>
                    <li class="list-group-item d-flex justify-content-between">
                        <span class="text-muted">Phone</span> <strong class="text-dark">${data.phone}</strong>
                    </li>
                    <li class="list-group-item">
                        <span class="text-muted d-block mb-1">Job Description / Role</span>
                        <div class="p-2 bg-light rounded small text-dark border">${data.job_description || "N/A"}</div>
                    </li>
                </ul>
            `;
        }
    });
}

function approveRequest(id, action) {
    fetch('/admin/approve-request', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({request_id: id, action: action})
    }).then(r => r.json()).then(d => {
        loadAdminRequests();
    });
}

function deleteRequest(id) {
    if(!confirm("Are you sure you want to PERMANENTLY delete this request?")) return;
    
    fetch(`/admin/delete-request/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${authToken}` }
    }).then(r => r.json()).then(d => {
        if(d.success) {
            loadAdminRequests();
        } else {
            alert("Error: " + (d.detail || "Could not delete"));
        }
    });
}

function handleReportAction(id, action) {
    let confirmMsg = action === 'Release' ? "Are you sure you want to release this report?" : "Are you sure you want to RE-SCAN this request? Status will change to Processing.";
    if(!confirm(confirmMsg)) return;
    
    fetch('/admin/review-action', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({request_id: id, action: action})
    }).then(r => r.json()).then(d => {
        alert(d.message);
        loadAdminRequests();
    });
}

function updateDashboardStats() {
    // Fetch Real Data from /dashboard/stats
    secureFetch('/dashboard/stats').then(r => r.json()).then(d => {
        // Fallback checks for old UI components
        if(document.getElementById('reportsCount')) document.getElementById('reportsCount').innerText = d.completed_reports;
        if(document.getElementById('dash_active_scans')) document.getElementById('dash_active_scans').innerText = d.active_scans;
        if(document.getElementById('dash_intrusions')) document.getElementById('dash_intrusions').innerText = d.intrusions;
        
        // Update new Modern UI Gauges dynamically (Risk derived from Subnet Health / Threats from intrusions / Scans from active/completed)
        let totalScore = 0;
        if (d.subnet_health && d.subnet_health.length > 0) {
            d.subnet_health.forEach(s => totalScore += s.score);
            totalScore = Math.floor(totalScore / d.subnet_health.length);
        } else {
            totalScore = 95; // Default safe if no subnets parsed
        }

        const riskScore = 100 - totalScore; // Risk is inverse of health
        const activeThreats = d.intrusions;
        const totalScans = d.completed_reports + d.active_scans;
        
        // Call the global function defined in index.html
        if (window.updateDashboardGauges) {
            window.updateDashboardGauges(riskScore, activeThreats, totalScans);
        }

        const threatEl = document.getElementById('dash_threat_level');
        if (threatEl) {
            threatEl.innerText = d.threat_level;
            if (d.threat_level === "HIGH") threatEl.className = "mb-0 text-danger pulse";
            else if (d.threat_level === "ELEVATED") threatEl.className = "mb-0 text-warning";
            else threatEl.className = "mb-0 text-success";
        }
        
        // Subnet Health
        const deptBody = document.getElementById('dept_status_body');
        if (d.subnet_health && d.subnet_health.length > 0) {
            deptBody.innerHTML = "";
            d.subnet_health.forEach(sub => {
                const color = sub.score >= 90 ? 'success' : (sub.score >= 70 ? 'warning' : 'danger');
                deptBody.innerHTML += `
                <div class="mb-3">
                    <div class="d-flex justify-content-between mb-1">
                        <span>${sub.subnet}</span>
                        <span class="text-${color} fw-bold">${sub.score}% Secure</span>
                    </div>
                    <div class="progress" style="height: 6px;">
                        <div class="progress-bar bg-${color}" style="width: ${sub.score}%"></div>
                    </div>
                </div>`;
            });
        } else {
            deptBody.innerHTML = '<div class="text-center text-muted small mt-4">No scan data available yet.</div>';
        }
        
        // Zone Status (Real-time update)
        if(d.zone_status) {
            const zoneList = document.getElementById('zone_status_list');
            if(zoneList) {
                zoneList.innerHTML = d.zone_status.map(z => {
                    let badgeClass = 'bg-success bg-opacity-10 text-success';
                    let iconClass = 'text-success';
                    if(z.status === 'Monitoring') { badgeClass = 'bg-warning bg-opacity-10 text-warning'; iconClass = 'text-warning'; }
                    if(z.status === 'Alert') { badgeClass = 'bg-danger bg-opacity-10 text-danger'; iconClass = 'text-danger'; }
                    
                    return `
                    <div class="list-group-item d-flex justify-content-between align-items-center py-3 border-light">
                        <div><i class="fas ${z.icon} me-2 ${iconClass}"></i> ${z.name}</div>
                        <span class="badge ${badgeClass} rounded-pill">${z.status}</span>
                    </div>`;
                }).join('');
            }
        }
        
    }).catch(e => console.error("Stats Error", e));
}

// --- Dashboard Visuals & Real-time Data ---
let trafficChart = null;
let dashboardInterval = null;

function initDashboard() {
    if (dashboardInterval) clearInterval(dashboardInterval);
    
    // Init Chart.js
    const ctx = document.getElementById('trafficChart')?.getContext('2d');
    if (ctx && !trafficChart) {
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{
                    label: 'Inbound (Mbps)',
                    data: Array(20).fill(0),
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Outbound (Mbps)',
                    data: Array(20).fill(0),
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#94a3b8' } } },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
                },
                animation: false
            }
        });
    }

    // Start Real-time Loop
    dashboardInterval = setInterval(() => {
        updateTrafficChart();
        fetchRealAlerts();
        updateDashboardStats();
    }, 2000);
}

function updateTrafficChart() {
    if (!trafficChart) return;
    
    secureFetch('/dashboard/traffic').then(r => r.json()).then(data => {
        const d1 = trafficChart.data.datasets[0].data;
        const d2 = trafficChart.data.datasets[1].data;
        
        d1.shift();
        d2.shift();
        
        d1.push(data.inbound_mbps);
        d2.push(data.outbound_mbps);
        
        trafficChart.update();
    }).catch(e => console.error("Traffic Error", e));
}

let lastAlertTime = "";

function fetchRealAlerts() {
    secureFetch('/dashboard/alerts').then(r => r.json()).then(data => {
        if (!data.alerts || data.alerts.length === 0) return;
        
        // Only add new alerts (simple check against top timestamp)
        const latest = data.alerts[0];
        if (latest.timestamp !== lastAlertTime) {
            // Clear feed if it's the first load to remove "Waiting..."
            const feed = document.getElementById('liveAlertsFeed');
            if (feed.innerText.includes("Waiting")) feed.innerHTML = "";
            
            // Add alert to list
            addAlert(latest.message, latest.severity, latest.source);
            lastAlertTime = latest.timestamp;
        }
    }).catch(e => console.error("Alerts Error", e));
}

function addAlert(msg, severity, source) {
    const feed = document.getElementById('liveAlertsFeed');
    if (!feed) return;
    
    const color = severity === 'High' ? 'danger' : 'warning';
    const item = document.createElement('div');
    item.className = 'list-group-item bg-transparent border-bottom border-light text-dark py-2 page-transition';
    item.innerHTML = `
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <span class="badge bg-${color} me-2">${severity}</span>
                <small class="text-muted">${new Date().toLocaleTimeString()}</small>
            </div>
            <small class="text-primary fw-bold" style="font-size: 0.8rem;">${source}</small>
        </div>
        <div class="mt-2 fw-medium">${msg}</div>
    `;
    
    feed.insertBefore(item, feed.firstChild);
    
    // Keep list short
    if (feed.children.length > 10) {
        feed.removeChild(feed.lastChild);
    }
}
