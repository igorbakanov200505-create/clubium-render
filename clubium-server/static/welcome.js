/* Redirect only after a successful server-side login, never on the login form. */
(() => {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  window.setTimeout(() => window.location.replace('/dashboard'), reducedMotion ? 500 : 2500);
})();
