(()=>{'use strict';
const $=(sel,root=document)=>root.querySelector(sel);
const $$=(sel,root=document)=>Array.from(root.querySelectorAll(sel));
const T={ru:{search:'Поиск по разделам',searchShort:'Поиск',hint:'Найти раздел…',close:'Закрыть',empty:'Раздел не найден',home:'Главная',palette:'Быстрый переход'},kk:{search:'Бөлімдер бойынша іздеу',searchShort:'Іздеу',hint:'Бөлімді табу…',close:'Жабу',empty:'Бөлім табылмады',home:'Басты бет',palette:'Жылдам өту'},en:{search:'Search sections',searchShort:'Search',hint:'Find a section…',close:'Close',empty:'No matching section',home:'Dashboard',palette:'Quick navigation'}};
let selected=0;
function lang(){return window.ClubiumI18n?.current?.()||'ru'}
function label(el){return el.textContent.trim().replace(/\s+/g,' ')}
function links(){return $$('.sidebar a.nav-link').filter(a=>a.getAttribute('href')?.startsWith('/')).map(a=>({url:a.getAttribute('href'),name:label(a),icon:a.querySelector('.nav-icon')?.innerHTML||''}));}
function palette(){return $('#nova-command-palette')}
function fillNav(){const root=$('#nova-mobile-nav');if(!root)return; const entries=links();root.innerHTML='';entries.forEach((entry,i)=>{let a=document.createElement('a');a.href=entry.url;a.className='mobile-nav-item'+(location.pathname===entry.url?' active':'');let ic=document.createElement('span');ic.className='mobile-nav-icon';ic.innerHTML=entry.icon;const caption=document.createElement('span');caption.textContent=entry.name;a.append(ic,caption);root.appendChild(a);});root.setAttribute('data-entries',String(entries.length));}
function renderResults(query=''){const root=$('#nova-command-results');if(!root)return; root.innerHTML='';const all=links(),items=all.filter(v=>v.name.toLocaleLowerCase().includes(query.toLocaleLowerCase().trim())); selected=0;items.forEach((v,i)=>{let a=document.createElement('a');a.href=v.url;a.className='palette-result'+(!i?' is-selected':'');const ic=document.createElement('span');ic.className='palette-result-icon';ic.innerHTML=v.icon;a.append(ic,document.createTextNode(v.name));const arrow=document.createElement('span');arrow.className='palette-arrow';arrow.textContent='↵';a.append(arrow);root.appendChild(a)});if(!items.length){const el=document.createElement('p');el.className='palette-empty';el.textContent=T[lang()].empty;root.appendChild(el);}}
function showPalette(){const dlg=palette();if(!dlg)return;renderResults();dlg.showModal();const inp=$('#nova-command-input');if(inp){inp.value='';inp.placeholder=T[lang()].hint;inp.focus()}}
function moveSelection(dir){const res=$$('.palette-result');if(!res.length)return;selected=Math.max(0,Math.min(res.length-1,selected+dir));res.forEach((r,i)=>r.classList.toggle('is-selected',i===selected));res[selected].scrollIntoView({block:'nearest'})}
function updateLabels(){const tx=T[lang()]||T.ru;const b=$('[data-nova-search]');if(b){b.setAttribute('aria-label',tx.search);b.title=tx.search+' Ctrl+K';const s=$('.search-hint',b);if(s)s.textContent=tx.searchShort;}const p=$('#nova-command-input');if(p)p.placeholder=tx.hint;const close=$('.palette-close');if(close)close.setAttribute('aria-label',tx.close);fillNav();}
function toast(text){const region=$('#nova-toast-region');if(!region)return;const el=document.createElement('div');el.className='nova-toast';el.textContent=text;region.appendChild(el);window.setTimeout(()=>el.remove(),4000)}
function init(){if($('[data-nova-search]')){
  $('[data-nova-search]').addEventListener('click',showPalette);
  $('.palette-close')?.addEventListener('click',()=>palette()?.close());
  palette()?.addEventListener('click',e=>{if(e.target===palette())palette().close()});
  $('#nova-command-input')?.addEventListener('input',e=>renderResults(e.target.value));
  $('#nova-command-input')?.addEventListener('keydown',e=>{if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();moveSelection(e.key==='ArrowDown'?1:-1)}if(e.key==='Enter'){const res=$$('.palette-result');if(res[selected]){window.location.href=res[selected].href}}});
  document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();showPalette()}});
}
updateLabels();document.addEventListener('clubium:language-changed',updateLabels);window.addEventListener('clubium:language-changed',updateLabels);
$$('dialog.modal').forEach(d=>{d.setAttribute('aria-modal','true')});
// Animated entrance is visual only, no data hidden from accessibility technology.
$$('.kpi, .club-card, .panel').slice(0,28).forEach((el,i)=>{el.style.setProperty('--entry-index',String(Math.min(i,8)))});
if('serviceWorker'in navigator&&location.protocol==='https:'){navigator.serviceWorker.register('/static/nova-sw.js').catch(()=>{});}
}
window.ClubiumNOVA={toast,showPalette};if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();