// Shared sidebar — single source of truth for all pages
(function () {
  const V = '?v=2';
  const links = [
    { href: '/dashboard.html', icon: 'fa-gauge-high',  label: 'Dashboard' },
    { href: '/alerts.html',    icon: 'fa-bell',        label: 'Alerts' },
    { href: '/incidents.html', icon: 'fa-file-shield', label: 'Incidents' },
    { href: '/ai_analyst.html',icon: 'fa-robot',       label: 'AI Analyst' },
    { href: '/virustotal.html',icon: 'fa-virus-slash', label: 'VirusTotal' },
    { href: '/reports.html',   icon: 'fa-chart-bar',   label: 'Reports' },
    { href: '/users.html',     icon: 'fa-users-gear',  label: 'Users' },
    { href: '/rules.html',     icon: 'fa-sliders',     label: 'Alert Rules' },
  ];

  const current = window.location.pathname;

  // Inject sidebar into any element with id="sidebar-nav"
  // Also create the nav if missing (handles old cached pages)
  let nav = document.getElementById('sidebar-nav');
  if (!nav) {
    const aside = document.querySelector('aside.sidebar');
    if (!aside) return;
    nav = document.createElement('nav');
    nav.id = 'sidebar-nav';
    nav.className = 'p-3 flex-1 space-y-1';
    const existingNav = aside.querySelector('nav');
    if (existingNav) existingNav.replaceWith(nav);
    else aside.appendChild(nav);
  }

  nav.innerHTML = links.map(l => {
    const active = current.endsWith(l.href) ? ' active' : '';
    const extra = l.href === '/alerts.html'
      ? ' <span id="alert-badge" class="ml-auto bg-red-500/20 text-red-400 text-xs px-2 py-0.5 rounded-full hidden"></span>'
      : '';
    return `<a href="${l.href}${V}" class="sidebar-link${active}">
      <span class="icon"><i class="fa-solid ${l.icon}"></i></span> ${l.label}${extra}
    </a>`;
  }).join('');
})();
