// SentriX API Client

const API_BASE = '';

function getToken() {
  return localStorage.getItem('sentrix_token');
}

function getUser() {
  try { return JSON.parse(localStorage.getItem('sentrix_user')); } catch { return null; }
}

function logout() {
  localStorage.removeItem('sentrix_token');
  localStorage.removeItem('sentrix_user');
  window.location.href = '/';
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (options.body instanceof FormData) delete headers['Content-Type'];

  const resp = await fetch(API_BASE + path, { ...options, headers });

  if (resp.status === 401) { logout(); return null; }

  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try { const d = await resp.json(); detail = d.detail || detail; } catch {}
    throw new Error(detail);
  }

  const ct = resp.headers.get('content-type') || '';
  if (ct.includes('application/json')) return resp.json();
  return resp;
}

async function apiGet(path, params = {}) {
  const qs = Object.keys(params).length ? '?' + new URLSearchParams(params) : '';
  return apiFetch(path + qs);
}

async function apiPost(path, body) {
  return apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
}

async function apiPatch(path, body) {
  return apiFetch(path, { method: 'PATCH', body: JSON.stringify(body) });
}

async function apiDelete(path) {
  return apiFetch(path, { method: 'DELETE' });
}

// Toast notifications
function showToast(message, type = 'success') {
  const existing = document.querySelectorAll('.toast');
  existing.forEach(t => t.remove());

  const icons = { success: 'fa-circle-check', error: 'fa-circle-exclamation', info: 'fa-circle-info' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i> ${message}`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// Format helpers
function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev?.toUpperCase() || 'N/A'}</span>`;
}

function statusBadge(status) {
  const label = (status || '').replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
  return `<span class="badge badge-${status}">${label}</span>`;
}

function timeAgo(dateStr) {
  if (!dateStr) return 'N/A';
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleString();
}

// Markdown-like renderer for AI responses
function renderMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>')
    .replace(/^---$/gm, '<hr>')
    .replace(/\| (.+?) \|/g, (m) => {
      // Simple table row
      const cells = m.split('|').filter(c => c.trim() && c.trim() !== '-'.repeat(c.trim().length));
      return '<tr>' + cells.map(c => `<td>${c.trim()}</td>`).join('') + '</tr>';
    })
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`)
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br>');
}

// Auth guard — call on every protected page
function requireAuth() {
  if (!getToken()) { window.location.href = '/'; return false; }
  const user = getUser();
  if (user) {
    document.querySelectorAll('.user-name').forEach(el => el.textContent = user.full_name);
    document.querySelectorAll('.user-role').forEach(el => el.textContent = user.role.toUpperCase());
    document.querySelectorAll('.user-avatar').forEach(el => {
      el.textContent = user.full_name?.charAt(0).toUpperCase() || 'U';
    });
  }
  return true;
}

// Active sidebar link
function setActiveSidebarLink(page) {
  document.querySelectorAll('.sidebar-link').forEach(link => {
    link.classList.toggle('active', link.dataset.page === page);
  });
}

// Pagination helper
function buildPagination(container, current, total, onChange) {
  container.innerHTML = '';
  if (total <= 1) return;

  const mkBtn = (label, page, disabled = false) => {
    const btn = document.createElement('button');
    btn.textContent = label;
    btn.disabled = disabled || page === current;
    btn.className = `px-3 py-1 rounded text-sm border transition ${
      page === current
        ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400'
        : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
    }`;
    if (!disabled) btn.addEventListener('click', () => onChange(page));
    return btn;
  };

  container.appendChild(mkBtn('«', 1, current === 1));
  container.appendChild(mkBtn('‹', current - 1, current === 1));
  for (let p = Math.max(1, current - 2); p <= Math.min(total, current + 2); p++) {
    container.appendChild(mkBtn(String(p), p));
  }
  container.appendChild(mkBtn('›', current + 1, current === total));
  container.appendChild(mkBtn('»', total, current === total));
}
