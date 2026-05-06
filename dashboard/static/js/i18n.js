/* PatchMind i18n — FR / EN */

const LANG_DATA = {
  fr: {
    code: 'fr', label: 'FR', flag: 'FR',
    'nav.analyze':           'Analyse',
    'nav.files':             'Mes fichiers',
    'nav.metrics':           'Métriques',
    'nav.history':           'Historique',
    'nav.projects':          'Projets',
    'nav.profile':           'Mon profil',
    'nav.admin':             'Admin Panel',
    'nav.logout':            'Déconnexion',
    'scan.upload_title':     'Upload fichier source',
    'scan.drop':             'Déposer un fichier à analyser',
    'scan.button':           'Lancer l\'analyse',
    'scan.scanners':         'Scanners à utiliser',
    'scan.github_title':     'Analyser un repo GitHub',
    'results.vulns':         'Vulnérabilités',
    'results.patches':       'Patches validés',
    'results.success':       'Taux de succès',
    'results.mttr':          'MTTR moyen',
    'severity.critical':     'Critique',
    'severity.high':         'Élevée',
    'severity.medium':       'Moyenne',
    'severity.low':          'Faible',
    'action.apply':          'Appliquer le patch',
    'action.copy':           'Copier',
    'action.copied':         'Copié !',
    'action.pdf':            'Rapport PDF',
    'action.excel':          'Export Excel',
    'action.reanalyze':      'Re-analyser',
    'action.false_positive': 'Faux positif',
    'action.assign':         'Assigner',
    'action.generate_test':  'Générer un test',
    'filter.all':            'Tous',
    'filter.severity':       'Sévérité',
    'filter.status':         'Statut',
    'filter.project':        'Projet',
    'filter.scanner':        'Scanner',
    'history.title':         'Historique des sessions',
    'history.filter_project':'Filtrer par projet',
    'admin.users':           'Utilisateurs',
    'admin.audit':           'Audit Log',
    'admin.monitoring':      'Monitoring',
    'onboard.title':         'Bienvenue sur PatchMind !',
    'onboard.next':          'Suivant',
    'onboard.back':          'Retour',
    'onboard.finish':        'C\'est parti !',
  },
  en: {
    code: 'en', label: 'EN', flag: 'EN',
    'nav.analyze':           'Analysis',
    'nav.files':             'My files',
    'nav.metrics':           'Metrics',
    'nav.history':           'History',
    'nav.projects':          'Projects',
    'nav.profile':           'My profile',
    'nav.admin':             'Admin Panel',
    'nav.logout':            'Sign out',
    'scan.upload_title':     'Upload source file',
    'scan.drop':             'Drop a file to analyze',
    'scan.button':           'Start analysis',
    'scan.scanners':         'Scanners to use',
    'scan.github_title':     'Analyze a GitHub repo',
    'results.vulns':         'Vulnerabilities',
    'results.patches':       'Validated patches',
    'results.success':       'Success rate',
    'results.mttr':          'Average MTTR',
    'severity.critical':     'Critical',
    'severity.high':         'High',
    'severity.medium':       'Medium',
    'severity.low':          'Low',
    'action.apply':          'Apply patch',
    'action.copy':           'Copy',
    'action.copied':         'Copied!',
    'action.pdf':            'PDF Report',
    'action.excel':          'Export Excel',
    'action.reanalyze':      'Re-analyze',
    'action.false_positive': 'False positive',
    'action.assign':         'Assign',
    'action.generate_test':  'Generate test',
    'filter.all':            'All',
    'filter.severity':       'Severity',
    'filter.status':         'Status',
    'filter.project':        'Project',
    'filter.scanner':        'Scanner',
    'history.title':         'Session history',
    'history.filter_project':'Filter by project',
    'admin.users':           'Users',
    'admin.audit':           'Audit Log',
    'admin.monitoring':      'Monitoring',
    'onboard.title':         'Welcome to PatchMind!',
    'onboard.next':          'Next',
    'onboard.back':          'Back',
    'onboard.finish':        'Let\'s go!',
  }
};

/* Current language — reads localStorage, falls back to 'fr' */
function _currentLang() {
  return localStorage.getItem('pm_lang') || 'fr';
}

/* t('key') — returns translated string for current language */
function t(key) {
  const data = LANG_DATA[_currentLang()] || LANG_DATA['fr'];
  return data[key] !== undefined ? data[key] : key;
}

/*
 * applyLang(lang) — apply translations to all data-i18n elements.
 * SVG-safe: when an element contains SVG children, only text nodes are
 * updated so icon() SVGs are not destroyed by textContent assignment.
 */
function applyLang(lang) {
  const data = LANG_DATA[lang] || LANG_DATA['fr'];

  /* Update lang button label */
  const flagEl  = document.getElementById('lang-flag');
  const labelEl = document.getElementById('lang-label');
  if (flagEl)  flagEl.textContent  = data.flag;
  if (labelEl) labelEl.textContent = data.label;

  /* Translate text content — SVG-aware */
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (data[key] === undefined) return;
    const val = data[key];

    if (el.querySelector('svg')) {
      /* Element contains an SVG icon: update only the trailing text node */
      let updated = false;
      el.childNodes.forEach(node => {
        if (node.nodeType === Node.TEXT_NODE && node.textContent.trim()) {
          node.textContent = val;
          updated = true;
        }
      });
      /* If no text node found, append one after the SVG */
      if (!updated) {
        el.appendChild(document.createTextNode(val));
      }
    } else {
      el.textContent = val;
    }
  });

  /* Translate placeholder attributes */
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (data[key] !== undefined) el.placeholder = data[key];
  });

  /* Translate title/tooltip attributes */
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    if (data[key] !== undefined) el.title = data[key];
  });

  /* Update <html lang=""> attribute */
  document.documentElement.lang = lang;
}

function toggleLang() {
  const next = _currentLang() === 'fr' ? 'en' : 'fr';
  localStorage.setItem('pm_lang', next);
  applyLang(next);
  fetch('/profile/lang', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({lang: next})
  }).catch(() => {});
}

/* Apply immediately (script is at end of body — DOM is ready) */
applyLang(_currentLang());

/* Also on DOMContentLoaded as a safety net for deferred rendering */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => applyLang(_currentLang()));
}
