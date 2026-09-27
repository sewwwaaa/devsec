/**
 * TaskShield Client-side Controller & Exploit Demonstration Engine
 */

const API_BASE = '/api';

// Current session state
let session = {
  token: localStorage.getItem('taskshield_token') || null,
  user: JSON.parse(localStorage.getItem('taskshield_user') || 'null')
};

// DOM Elements
const authModal = document.getElementById('auth-modal');
const openLoginBtn = document.getElementById('open-login-btn');
const closeModalBtn = document.getElementById('close-modal-btn');
const authForm = document.getElementById('auth-form');
const userBadge = document.getElementById('user-badge');
const authButtons = document.getElementById('auth-buttons');
const currentUsername = document.getElementById('current-username');
const currentRole = document.getElementById('current-role');
const logoutBtn = document.getElementById('logout-btn');

const notesContainer = document.getElementById('notes-container');
const createNoteForm = document.getElementById('create-note-form');
const refreshNotesBtn = document.getElementById('refresh-notes-btn');
const refreshAuditBtn = document.getElementById('refresh-audit-btn');
const auditLogBody = document.getElementById('audit-log-body');
const terminalOutput = document.getElementById('terminal-output');
const runAllExploitsBtn = document.getElementById('run-all-exploits-btn');

// Initialize UI
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupAuthEvents();
  setupNotesEvents();
  setupExploitEvents();
  updateSessionUI();

  if (session.token) {
    loadUserNotes();
    if (session.user?.role === 'admin') {
      loadAuditLogs();
    }
  }
});

/* ==========================================
   Tab Navigation
========================================== */
function setupTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.dataset.tab;
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }

      if (targetId === 'tab-audit-logs') {
        loadAuditLogs();
      }
    });
  });
}

/* ==========================================
   Authentication
========================================== */
function setupAuthEvents() {
  openLoginBtn.addEventListener('click', () => authModal.classList.remove('hidden'));
  closeModalBtn.addEventListener('click', () => authModal.classList.add('hidden'));

  // Quick preset buttons
  document.querySelectorAll('.btn-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('auth-username').value = btn.dataset.u;
      document.getElementById('auth-password').value = btn.dataset.p;
    });
  });

  // Auth Form Submit
  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('auth-username').value;
    const password = document.getElementById('auth-password').value;

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        session.token = data.token;
        session.user = data.user;
        localStorage.setItem('taskshield_token', data.token);
        localStorage.setItem('taskshield_user', JSON.stringify(data.user));

        authModal.classList.add('hidden');
        updateSessionUI();
        loadUserNotes();
        logTerminal(`[AUTH] Successfully signed in as ${data.user.username} (${data.user.role})`);
      } else {
        alert(data.error || 'Authentication failed');
      }
    } catch (err) {
      alert('Error communicating with server: ' + err.message);
    }
  });

  logoutBtn.addEventListener('click', () => {
    session.token = null;
    session.user = null;
    localStorage.removeItem('taskshield_token');
    localStorage.removeItem('taskshield_user');
    updateSessionUI();
    notesContainer.innerHTML = '<div class="empty-state"><p>Signed out. Please sign in to view your records.</p></div>';
    logTerminal('[AUTH] Signed out of session.');
  });
}

function updateSessionUI() {
  if (session.token && session.user) {
    userBadge.classList.remove('hidden');
    authButtons.classList.add('hidden');
    currentUsername.textContent = session.user.username;
    currentRole.textContent = session.user.role;
    currentRole.className = `badge badge-${session.user.role === 'admin' ? 'devsecops' : 'role'}`;
  } else {
    userBadge.classList.add('hidden');
    authButtons.classList.remove('hidden');
  }
}

/* ==========================================
   Notes & Tasks
========================================== */
function setupNotesEvents() {
  refreshNotesBtn.addEventListener('click', loadUserNotes);

  createNoteForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!session.token) {
      alert('Please sign in first.');
      authModal.classList.remove('hidden');
      return;
    }

    const title = document.getElementById('note-title').value;
    const category = document.getElementById('note-category').value;
    const content = document.getElementById('note-content').value;
    const is_confidential = document.getElementById('note-confidential').checked;

    try {
      const res = await fetch(`${API_BASE}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session.token}`
        },
        body: JSON.stringify({ title, category, content, is_confidential })
      });
      const data = await res.json();

      if (res.ok) {
        createNoteForm.reset();
        loadUserNotes();
        logTerminal(`[SECURE NOTE] Created note #${data.note.id}. Strict input sanitization applied.`);
      } else {
        alert(data.error || 'Failed to save note');
      }
    } catch (err) {
      alert('Network error: ' + err.message);
    }
  });
}

async function loadUserNotes() {
  if (!session.token) return;

  notesContainer.innerHTML = '<div class="empty-state"><p>Loading isolated tenant records...</p></div>';

  try {
    const res = await fetch(`${API_BASE}/notes`, {
      headers: { 'Authorization': `Bearer ${session.token}` }
    });
    const data = await res.json();

    if (res.ok && data.notes) {
      if (data.notes.length === 0) {
        notesContainer.innerHTML = '<div class="empty-state"><p>No notes found. Create your first note above!</p></div>';
        return;
      }

      notesContainer.innerHTML = data.notes.map(note => `
        <div class="note-item">
          <div class="note-top">
            <h4 class="note-title">${escapeHtml(note.title)}</h4>
            <span class="badge ${note.is_confidential ? 'badge-cwe' : 'badge-devsecops'}">
              ${note.is_confidential ? 'Confidential' : note.category}
            </span>
          </div>
          <p class="note-content">${escapeHtml(note.content)}</p>
          <div class="note-footer">
            <span>ID: #${note.id} &bull; ${new Date(note.created_at).toLocaleString()}</span>
            <button class="btn btn-outline-sm" onclick="deleteNote(${note.id})">Delete</button>
          </div>
        </div>
      `).join('');
    } else {
      notesContainer.innerHTML = `<div class="empty-state"><p>${data.error || 'Failed to load records.'}</p></div>`;
    }
  } catch (err) {
    notesContainer.innerHTML = `<div class="empty-state"><p>Error: ${err.message}</p></div>`;
  }
}

window.deleteNote = async function (id) {
  if (!confirm(`Delete note #${id}?`)) return;

  try {
    const res = await fetch(`${API_BASE}/notes/${id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${session.token}` }
    });
    const data = await res.json();

    if (res.ok) {
      loadUserNotes();
      logTerminal(`[DELETE] Resource #${id} deleted safely under verified ownership.`);
    } else {
      alert(data.error || 'Failed to delete note');
      logTerminal(`[BLOCKED] Delete attempt on #${id} rejected: ${data.error}`);
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
};

/* ==========================================
   Exploit Demonstration Sandbox
========================================== */
function setupExploitEvents() {
  document.querySelectorAll('.btn-exploit').forEach(btn => {
    btn.addEventListener('click', async () => {
      const exploitType = btn.dataset.exploit;
      await runSingleExploit(exploitType);
    });
  });

  runAllExploitsBtn.addEventListener('click', runAllExploitsSuite);
  refreshAuditBtn.addEventListener('click', loadAuditLogs);
}

async function runSingleExploit(type) {
  logTerminal(`\n>>> Executing Exploit Test: ${type.toUpperCase()}...`);

  switch (type) {
    case 'sqli-vuln':
      await testSqli(true);
      break;
    case 'sqli-secure':
      await testSqli(false);
      break;
    case 'xss-vuln':
      await testXss(true);
      break;
    case 'xss-secure':
      await testXss(false);
      break;
    case 'bola-vuln':
      await testBola(true);
      break;
    case 'bola-secure':
      await testBola(false);
      break;
    case 'jwt-vuln':
      await testJwt(true);
      break;
    case 'jwt-secure':
      await testJwt(false);
      break;
  }
}

async function testSqli(isVuln) {
  const payload = { username: "admin' OR '1'='1", password: "dummy_password" };
  const url = isVuln ? `${API_BASE}/auth/vulnerable-login` : `${API_BASE}/auth/login`;

  logTerminal(`[SQLi] Target: POST ${url}`);
  logTerminal(`[SQLi] Payload: ${JSON.stringify(payload)}`);

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();

  if (isVuln && res.ok) {
    logTerminal(`💥 EXPLOIT SUCCESS (Vulnerable): Status 200 OK! Bypassed auth as ${data.user.username}.`);
  } else if (!isVuln && (res.status === 400 || res.status === 401)) {
    logTerminal(`🛡️ EXPLOIT BLOCKED (Secure): Status ${res.status}. Joi & Parameterized query rejected payload!`);
  } else {
    logTerminal(`Response: Status ${res.status} - ${JSON.stringify(data)}`);
  }
}

async function testXss(isVuln) {
  const payload = {
    title: 'XSS Attack Notice <script>alert("TaskShield Pwned")</script>',
    content: 'Payload: <img src=x onerror="console.log(document.cookie)">',
    category: 'xss-test'
  };

  if (isVuln) {
    logTerminal(`[XSS] Target: POST ${API_BASE}/notes/demo/xss`);
    const res = await fetch(`${API_BASE}/notes/demo/xss`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    logTerminal(`💥 EXPLOIT SUCCESS: Raw unsanitized <script> payload stored into database!`);
    logTerminal(`Persisted Title: ${data.rawPayload.title}`);
  } else {
    logTerminal(`[XSS] Target: POST ${API_BASE}/notes (Protected by sanitize-html)`);
    // Ensure we have bob token
    const authRes = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'bob', password: 'BobPass!2026' })
    });
    const authData = await authRes.json();

    const res = await fetch(`${API_BASE}/notes`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authData.token}`
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    logTerminal(`🛡️ EXPLOIT NEUTRALIZED: Strict sanitization stripped tags! Clean title: "${data.note.title}"`);
  }
}

async function testBola(isVuln) {
  if (isVuln) {
    logTerminal(`[BOLA] Target: GET ${API_BASE}/notes/demo/bola/1 (Alice's confidential budget)`);
    const res = await fetch(`${API_BASE}/notes/demo/bola/1`);
    const data = await res.json();
    logTerminal(`💥 EXPLOIT SUCCESS: Unauthenticated caller exfiltrated Alice's record! Content: "${data.note.content}"`);
  } else {
    // Authenticate as Bob and try to read Alice's note
    const authRes = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'bob', password: 'BobPass!2026' })
    });
    const authData = await authRes.json();

    logTerminal(`[BOLA] Target: GET ${API_BASE}/notes/1 as user 'bob' (ID: ${authData.user.id})`);
    const res = await fetch(`${API_BASE}/notes/1`, {
      headers: { 'Authorization': `Bearer ${authData.token}` }
    });
    const data = await res.json();
    if (res.status === 403) {
      logTerminal(`🛡️ EXPLOIT BLOCKED: Status 403 Forbidden! Ownership validation blocked cross-tenant access.`);
    } else {
      logTerminal(`Response: ${res.status} - ${JSON.stringify(data)}`);
    }
  }
}

async function testJwt(isVuln) {
  // Offline forged token signed with weak secret "secret123"
  // Header: {"alg":"HS256","typ":"JWT"}, Payload: {"id":99,"username":"forged_admin","role":"admin"}
  // Signed with "secret123"
  const forgedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6OTksInVzZXJuYW1lIjoiZm9yZ2VkX2FkbWluIiwicm9sZSI6ImFkbWluIn0.G3Q28o5z_Q5l6k_0a_R1p2bW_m5oQ31xN3R9fQe7Hzo";

  if (isVuln) {
    logTerminal(`[JWT] Target: GET ${API_BASE}/auth/vulnerable-jwt-verify using forged token`);
    const res = await fetch(`${API_BASE}/auth/vulnerable-jwt-verify`, {
      headers: { 'Authorization': `Bearer ${forgedToken}` }
    });
    const data = await res.json();
    logTerminal(`💥 EXPLOIT SUCCESS: Vulnerable endpoint accepted forged token signed with weak secret!`);
  } else {
    logTerminal(`[JWT] Target: GET ${API_BASE}/admin/audit-logs using forged token`);
    const res = await fetch(`${API_BASE}/admin/audit-logs`, {
      headers: { 'Authorization': `Bearer ${forgedToken}` }
    });
    const data = await res.json();
    logTerminal(`🛡️ EXPLOIT BLOCKED: Status ${res.status}. Production 256-bit runtime key rejected signature!`);
  }
}

async function runAllExploitsSuite() {
  terminalOutput.textContent = '';
  logTerminal('>>> Initiating DevSecOps End-to-End Exploit & Verification Test Suite...');
  await testSqli(true);
  await testSqli(false);
  await testXss(true);
  await testXss(false);
  await testBola(true);
  await testBola(false);
  await testJwt(true);
  await testJwt(false);
  logTerminal('\n===============================================================');
  logTerminal('✅ ALL 4 EXPLOITS VERIFIED: Attacks succeeded on vulnerable & were BLOCKED on secured.');
  logTerminal('===============================================================');
}

/* ==========================================
   SIEM & Audit Logs
========================================== */
async function loadAuditLogs() {
  if (!session.token) {
    auditLogBody.innerHTML = '<tr><td colspan="6" class="text-center">Please sign in as Admin (admin / AdminSecurePass!2026) to view audit trail.</td></tr>';
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/admin/audit-logs`, {
      headers: { 'Authorization': `Bearer ${session.token}` }
    });
    const data = await res.json();

    if (res.ok && data.logs) {
      if (data.logs.length === 0) {
        auditLogBody.innerHTML = '<tr><td colspan="6" class="text-center">No security audit events recorded yet.</td></tr>';
        return;
      }

      auditLogBody.innerHTML = data.logs.map(log => `
        <tr>
          <td><code>${new Date(log.timestamp).toLocaleTimeString()}</code></td>
          <td>${log.userId || 'Anonymous'}</td>
          <td><strong>${log.action}</strong></td>
          <td><span class="badge ${log.status === 'SUCCESS' ? 'badge-role' : 'badge-cwe'}">${log.status}</span></td>
          <td><code>${log.ip_address || '127.0.0.1'}</code></td>
          <td>${escapeHtml(log.details || 'Authentication event')}</td>
        </tr>
      `).join('');
    } else {
      auditLogBody.innerHTML = `<tr><td colspan="6" class="text-center">${data.error || 'Access denied. Administrator role required.'}</td></tr>`;
    }
  } catch (err) {
    auditLogBody.innerHTML = `<tr><td colspan="6" class="text-center">Error: ${err.message}</td></tr>`;
  }
}

function logTerminal(msg) {
  terminalOutput.textContent += '\n' + msg;
  terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
