/* Eye button reveals only the text being typed in a field, never a database password. */
(() => {
  'use strict';
  const eye = '<svg viewBox="0 0 24 24" width="21" height="21" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.8-6.5 10-6.5S22 12 22 12s-3.8 6.5-10 6.5S2 12 2 12Z"/><circle cx="12" cy="12" r="2.6"/></svg>';
  const eyeOff = '<svg viewBox="0 0 24 24" width="21" height="21" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3 21 21M9.9 5.8A11 11 0 0 1 12 5.5C18.2 5.5 22 12 22 12a16.4 16.4 0 0 1-4 4.4M6 7.2A17 17 0 0 0 2 12s3.8 6.5 10 6.5a10.8 10.8 0 0 0 3.1-.5"/><path d="M10.1 10.1a2.7 2.7 0 0 0 3.8 3.8"/></svg>';
  function translate(text){return window.ClubiumI18n ? window.ClubiumI18n.tr(text) : text}
  function sync(button){
    const input=document.getElementById(button.dataset.togglePassword);
    if(!input)return;
    const visible=input.type==='text';
    button.innerHTML=visible?eyeOff:eye;
    button.dataset.visible=visible?'true':'false';
    button.setAttribute('aria-pressed',String(visible));
    button.setAttribute('aria-label',translate(visible?'Скрыть пароль':'Показать пароль'));
    button.title=translate(visible?'Скрыть пароль':'Показать пароль');
  }
  function init(){document.querySelectorAll('button[data-toggle-password]').forEach(sync)}
  document.addEventListener('click',e=>{
    const button=e.target.closest('button[data-toggle-password]');
    if(!button)return;
    const input=document.getElementById(button.dataset.togglePassword);
    if(!input)return;
    input.type=input.type==='password'?'text':'password';
    sync(button);
  });
  window.addEventListener('clubium:language-changed',init);
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
