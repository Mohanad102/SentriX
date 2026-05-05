// Shared sidebar — single source of truth for all pages
(function () {
  const user = JSON.parse(localStorage.getItem('sentrix_user') || '{}');
  const role = user.role || '';
  const isL1    = role === 'soc_analyst_l1';
  const isL2    = role === 'soc_analyst_l2';
  const isAdmin = role === 'admin';
  const canIR   = (role === 'incident_responder' || isAdmin);

  const groups = [
    {
      label: 'Navigation',
      links: [
        { href: '/dashboard.html',    icon: 'fa-gauge-high',   label: 'Dashboard' },
        { href: '/alerts.html',       icon: 'fa-bell',         label: 'Alerts', badge: true },
        { href: '/incidents.html', icon: 'fa-shield-virus', label: 'IR Dashboard' },
        { href: '/tickets.html',      icon: 'fa-ticket',       label: 'Tickets' },
      ]
    },
    {
      label: 'Tools',
      links: [
        { href: '/ai_analyst.html', icon: 'fa-robot',       label: 'AI Analyst' },
        { href: '/virustotal.html', icon: 'fa-virus-slash',  label: 'VirusTotal' },
      ]
    },
    {
      label: 'Admin',
      adminOnly: true,
      links: [
        { href: '/users.html', icon: 'fa-users-gear', label: 'Users' },
        { href: '/rules.html', icon: 'fa-sliders',    label: 'Alert Rules' },
      ]
    },
  ];

  const current = window.location.pathname;

  // Replace or create the aside
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

  const navHtml = groups
    .filter(g => !(g.adminOnly && !isAdmin))
    .map(g => `
    <div class="sidebar-section">${g.label}</div>
    ${g.links.filter(l => !(l.irOnly && !canIR)).map(l => {
      const active = current.endsWith(l.href) || current.endsWith(l.href.replace('.html','')) ? ' active' : '';
      const badge  = l.badge
        ? ` <span id="alert-badge" class="ml-auto text-xs px-1.5 py-0.5 rounded-full hidden"
              style="background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)"></span>`
        : '';
      const irBadge = l.irOnly
        ? ` <span id="ir-notif-badge" class="ml-auto text-xs px-1.5 py-0.5 rounded-full hidden"
              style="background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)"></span>`
        : '';
      return `<a href="${l.href}" class="sidebar-link${active}">
        <span class="icon"><i class="fa-solid ${l.icon}"></i></span> ${l.label}${badge}${irBadge}
      </a>`;
    }).join('')}`
  ).join('');

  const userHtml = `
    <div class="p-3" style="border-top:1px solid rgba(255,255,255,0.05);">
      <div class="flex items-center gap-3 px-2 py-2 rounded-xl"
        style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.04);">
        <div class="w-8 h-8 rounded-full flex items-center justify-center text-emerald-400 font-bold text-sm user-avatar"
          style="background:linear-gradient(135deg,rgba(16,185,129,0.2),rgba(16,185,129,0.05));border:1px solid rgba(16,185,129,0.25);">A</div>
        <div class="flex-1 min-w-0">
          <p class="text-sm font-medium text-white truncate user-name">Admin</p>
          <p class="user-role" style="font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.06em;">Admin</p>
        </div>
        <button onclick="logout()" style="color:#475569;background:none;border:none;cursor:pointer;font-size:0.875rem;transition:color 0.2s;"
          onmouseover="this.style.color='#f87171'" onmouseout="this.style.color='#475569'" title="Logout">
          <i class="fa-solid fa-right-from-bracket"></i>
        </button>
      </div>
    </div>`;

  aside.innerHTML = logoHtml + `<nav class="p-3 flex-1 space-y-0.5">${navHtml}</nav>` + userHtml;

  // Poll unread notifications and show on IR badge
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
