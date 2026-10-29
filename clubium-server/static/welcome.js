/* After authentication, return to the exact protected page the user opened.
   The path comes from server-side session and is constrained to local URLs. */
(() => {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const link = document.querySelector('.welcome-skip');
  const raw = link?.getAttribute('href') || '/dashboard';
  let destination = '/dashboard';
  if (raw.startsWith('/') && !raw.startsWith('//') && !raw.includes('\\')) {
    const parsed = new URL(raw, window.location.origin);
    if (parsed.origin === window.location.origin) destination = parsed.pathname + parsed.search;
  }
  window.setTimeout(() => window.location.replace(destination), reducedMotion ? 500 : 2500);
})();
