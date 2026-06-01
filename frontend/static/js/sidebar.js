// Shared sidebar — single source of truth for all pages
(function () {
  const user = JSON.parse(localStorage.getItem('sentrix_user') || '{}');
  const role = user.role || '';
  const isL1    = role === 'soc_analyst_l1';
  const isL2    = role === 'soc_analyst_l2';
  const isAdmin = role === 'admin';
  const isIR    = role === 'incident_responder';
  const canIR   = isIR || isAdmin;

  // Role display labels
  const roleLabels = {
    admin:              'Administrator',
    soc_analyst_l1:     'SOC Analyst L1',
    soc_analyst_l2:     'SOC Analyst L2',
    incident_responder: 'Incident Responder',
  };

  const groups = [
    {
      label: 'Navigation',
      links: [
        { href: '/dashboard.html', icon: 'fa-gauge-high',   label: 'Dashboard',    roles: ['admin', 'soc_analyst_l1', 'soc_analyst_l2', 'incident_responder'] },
        { href: '/alerts.html',    icon: 'fa-bell',          label: 'Alerts',       badge: 'alert-badge', roles: ['admin', 'soc_analyst_l1', 'soc_analyst_l2', 'incident_responder'] },
        { href: '/tickets.html',   icon: 'fa-ticket',        label: 'Tickets',      roles: ['admin', 'soc_analyst_l1', 'soc_analyst_l2', 'incident_responder'] },
        { href: '/incidents.html', icon: 'fa-shield-virus',  label: 'IR Dashboard', roles: ['admin', 'incident_responder'], badge: 'ir-notif-badge' },
      ]
    },
    {
      label: 'Tools',
      links: [
        { href: '/ai_analyst.html', icon: 'fa-robot',                  label: 'AI Analyst',  roles: ['admin', 'soc_analyst_l2'] },
        { href: '/virustotal.html', icon: 'fa-virus-slash',             label: 'VirusTotal',  roles: ['admin', 'soc_analyst_l1', 'soc_analyst_l2', 'incident_responder'] },
        { href: '/agents.html',     icon: 'fa-network-wired',           label: 'Agents',      roles: ['admin', 'soc_analyst_l2'] },
      ]
    },
    {
      label: 'Admin',
      adminOnly: true,
      links: [
        { href: '/users.html',        icon: 'fa-users-gear', label: 'Users',         roles: ['admin'] },
        { href: '/rules.html',        icon: 'fa-sliders',    label: 'Alert Rules',   roles: ['admin'] },
        { href: '/integrations.html', icon: 'fa-plug',       label: 'Integrations',  roles: ['admin'] },
      ]
    },
  ];

  const current = window.location.pathname;

  let aside = document.querySelector('aside.sidebar');
  if (!aside) return;

  const logoHtml = `
    <div class="p-5" style="border-bottom:1px solid rgba(16,185,129,0.08);">
      <div class="flex items-center gap-3 sidebar-logo-glow">
        <div class="w-9 h-9 rounded-xl flex items-center justify-center relative"
          style="background:linear-gradient(135deg,rgba(16,185,129,0.2),rgba(16,185,129,0.05));border:1px solid rgba(16,185,129,0.3);box-shadow:0 0 20px rgba(16,185,129,0.15);">
          <i class="fa-solid fa-shield-halved text-emerald-400" style="font-size:1rem;"></i>
        </div>
        <div>
          <div class="text-white font-bold text-lg tracking-tight">Sentri<span class="text-emerald-400">X</span></div>
          <div style="font-size:0.6rem;color:#475569;letter-spacing:0.08em;">SOC PLATFORM</div>
        </div>
      </div>
    </div>`;

  // Role banners shown at top of sidebar nav
  const l1BannerHtml = isL1 ? `
    <div class="mx-3 mt-3 mb-1 px-3 py-2 rounded-xl flex items-center gap-2"
      style="background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.2);">
      <i class="fa-solid fa-user-shield text-blue-400 text-xs"></i>
      <span class="text-blue-300 text-xs font-medium">L1 Analyst View</span>
    </div>` : '';

  const l2BannerHtml = isL2 ? `
    <div class="mx-3 mt-3 mb-1 px-3 py-2 rounded-xl flex items-center gap-2"
      style="background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.2);">
      <i class="fa-solid fa-magnifying-glass-chart text-purple-400 text-xs"></i>
      <span class="text-purple-300 text-xs font-medium">L2 Investigator View</span>
    </div>` : '';

  const irBannerHtml = isIR ? `
    <div class="mx-3 mt-3 mb-1 px-3 py-2 rounded-xl flex items-center gap-2"
      style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.22);">
      <i class="fa-solid fa-shield-virus text-red-400 text-xs"></i>
      <span class="text-red-300 text-xs font-medium">IR Responder View</span>
    </div>` : '';

  const navHtml = groups
    .filter(g => !(g.adminOnly && !isAdmin && !isL2))
    .map(g => {
      const visibleLinks = g.links.filter(l => l.roles.includes(role));
      if (!visibleLinks.length) return '';
      return `
        <div class="sidebar-section">${g.label}</div>
        ${visibleLinks.map(l => {
          const active = current.endsWith(l.href) || current.endsWith(l.href.replace('.html', '')) ? ' active' : '';
          const badge  = l.badge
            ? ` <span id="${l.badge}" class="ml-auto text-xs px-1.5 py-0.5 rounded-full hidden"
                  style="background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)"></span>`
            : '';
          return `<a href="${l.href}" class="sidebar-link${active}">
            <span class="icon"><i class="fa-solid ${l.icon}"></i></span> ${l.label}${badge}
          </a>`;
        }).join('')}`;
    }).join('');

  const userHtml = `
    <div class="p-3" style="border-top:1px solid rgba(255,255,255,0.05);">
      <div class="flex items-center gap-3 px-2 py-2 rounded-xl"
        style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.04);">
        <div class="w-8 h-8 rounded-full flex items-center justify-center text-emerald-400 font-bold text-sm user-avatar"
          style="background:linear-gradient(135deg,rgba(16,185,129,0.2),rgba(16,185,129,0.05));border:1px solid rgba(16,185,129,0.25);">
          ${(user.full_name || 'U').charAt(0).toUpperCase()}
        </div>
        <div class="flex-1 min-w-0">
          <p class="text-sm font-medium text-white truncate user-name">${user.full_name || user.username || 'User'}</p>
          <p class="user-role" style="font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.06em;">
            ${roleLabels[role] || role}
          </p>
        </div>
        <button id="sidebar-theme-btn" onclick="window.__sentrixToggleTheme()" style="color:#475569;background:none;border:none;cursor:pointer;font-size:0.875rem;transition:color 0.2s;"
          onmouseover="this.style.color='#a3e635'" onmouseout="this.style.color='#475569'" title="Toggle theme">
          <i id="sidebar-theme-icon" class="fa-solid fa-moon"></i>
        </button>
        <button onclick="logout()" style="color:#475569;background:none;border:none;cursor:pointer;font-size:0.875rem;transition:color 0.2s;"
          onmouseover="this.style.color='#f87171'" onmouseout="this.style.color='#475569'" title="Logout">
          <i class="fa-solid fa-right-from-bracket"></i>
        </button>
      </div>
    </div>`;

  aside.innerHTML = logoHtml + l1BannerHtml + l2BannerHtml + irBannerHtml + `<nav class="p-3 flex-1 space-y-0.5 overflow-y-auto">${navHtml}</nav>` + userHtml;

  // Poll alert badge for all roles
  async function pollAlertBadge() {
    try {
      const token = localStorage.getItem('sentrix_token');
      if (!token) return;
      const params = isL1 ? '?status=open&assigned_to=L1+Analyst&page_size=1' : '?status=open&page_size=1';
      const r = await fetch('/api/alerts' + params, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) return;
      const d = await r.json();
      const badge = document.getElementById('alert-badge');
      if (badge && d.total > 0) {
        badge.textContent = d.total > 99 ? '99+' : d.total;
        badge.classList.remove('hidden');
      }
    } catch {}
  }
  pollAlertBadge();
  setInterval(pollAlertBadge, 60000);

  // ── Theme (global, runs on every page) ───────────────────────
  const THEME_KEY = 'sentrix_theme';
  function _applyTheme(theme) {
    const body = document.getElementById('body');
    const icon = document.getElementById('sidebar-theme-icon');
    // also sync dashboard's own icon if present
    const dashIcon = document.getElementById('theme-icon');
    if (theme === 'light') {
      if (body) body.classList.add('light-mode');
      if (icon) icon.className = 'fa-solid fa-sun';
      if (dashIcon) dashIcon.className = 'fa-solid fa-sun text-sm';
    } else {
      if (body) body.classList.remove('light-mode');
      if (icon) icon.className = 'fa-solid fa-moon';
      if (dashIcon) dashIcon.className = 'fa-solid fa-moon text-sm';
    }
  }
  window.__sentrixToggleTheme = function () {
    const cur = localStorage.getItem(THEME_KEY) || 'dark';
    const next = cur === 'dark' ? 'light' : 'dark';
    localStorage.setItem(THEME_KEY, next);
    _applyTheme(next);
  };
  _applyTheme(localStorage.getItem(THEME_KEY) || 'dark');

  // Poll IR notifications (non-L1 only)
  if (canIR) {
    async function pollIRNotifs() {
      try {
        const token = localStorage.getItem('sentrix_token');
        if (!token) return;
        const r = await fetch('/api/ir/notifications?unread_only=true&limit=1', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!r.ok) return;
        const d = await r.json();
        const badge = document.getElementById('ir-notif-badge');
        if (badge) {
          if (d.unread_count > 0) {
            badge.textContent = d.unread_count > 99 ? '99+' : d.unread_count;
            badge.classList.remove('hidden');
          } else {
            badge.classList.add('hidden');
          }
        }
      } catch {}
    }
    pollIRNotifs();
    setInterval(pollIRNotifs, 30000);
  }
})();
