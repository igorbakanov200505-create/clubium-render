(() => {
'use strict';
const paths={
 dashboard:'<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/><rect x="13" y="10" width="8" height="11" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/>',
 clubs:'<path d="M12 22V11m-7 3v7m14-7v7M4 11l8-8 8 8M2 21h20"/>',
 students:'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m18 0v-2a4 4 0 0 0-3-3.9M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm8-7a4 4 0 0 1 0 8"/>',
 attendance:'<rect x="3" y="4" width="18" height="17" rx="2"/><path d="M8 2v4m8-4v4M3 10h18m-12 5 2 2 4-4"/>',
 schedule:'<rect x="3" y="4" width="18" height="17" rx="2"/><path d="M8 2v4m8-4v4M3 10h18M7 14h3m4 0h3m-10 4h3"/>',
 portfolio:'<path d="m12 3 2.6 5.3 5.8.9-4.2 4.1 1 5.8-5.2-2.8-5.2 2.8 1-5.8-4.2-4.1 5.8-.9L12 3Z"/>',
 talent:'<path d="m12 2 1.9 6.1L20 10l-6.1 1.9L12 18l-1.9-6.1L4 10l6.1-1.9L12 2Zm7 15 .8 2.2L22 20l-2.2.8L19 23l-.8-2.2L16 20l2.2-.8L19 17Z"/>',
 assistant:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h8M8 11h8M8 15h5"/>',
 reports:'<path d="M4 20V10m5 10V4m5 16v-7m5 7V7"/>',
 users:'<circle cx="9" cy="8" r="4"/><path d="M2 21v-2a7 7 0 0 1 14 0v2m3-12v6m-3-3h6"/>'};
function svg(slug){return '<svg class="navigation-svg" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+paths[slug]+'</svg>'}
function init(){
  document.querySelectorAll('.sidebar a.nav-link').forEach(a=>{
    const slug=(a.getAttribute('href')||'').replace(/^\//,'').split('/')[0];
    const slot=a.querySelector('.nav-icon');
    if(slot&&paths[slug])slot.innerHTML=svg(slug);
  });
  document.querySelectorAll('dialog.modal').forEach(dialog=>{
    dialog.addEventListener('click',e=>{if(e.target===dialog)dialog.close()});
  });
  document.querySelectorAll('form').forEach(form=>{
    form.addEventListener('submit',()=>{
      const b=form.querySelector('button[type="submit"],button:not([type])');
      if(b&&!b.hasAttribute('data-no-loading'))b.classList.add('submitting');
    });
  });
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
