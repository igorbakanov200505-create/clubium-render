/* Only activates on admin account registration/edit forms. */
(function(){
  'use strict';
  const root=document.querySelector('[data-user-registration]');
  if(!root){
    const created=document.querySelector('[data-created-account]');
    if(!created)return;
    const login=created.querySelector('[data-copy-login]')?.textContent?.trim()||'';
    const password=created.querySelector('[data-copy-password]')?.textContent?.trim()||'';
    created.querySelectorAll('[data-copy-account]').forEach(button=>button.addEventListener('click',async()=>{
      const value=button.dataset.copyAccount==='login'?login:button.dataset.copyAccount==='password'?password:'Логин: '+login+'\nВременный пароль: '+password;
      try{await navigator.clipboard.writeText(value);button.textContent='Скопировано ✓'}
      catch(_err){button.textContent='Не удалось скопировать — выделите текст'}
    }));
    return;
  }
  const form=root.querySelector('#registrationForm');
  const cards=[...root.querySelectorAll('[data-role-panel]')];
  const radios=[...root.querySelectorAll('input[type="radio"][name="role"]')];
  const fixed=form.querySelector('input[type="hidden"][name="role"]');
  const schoolClass=form.querySelector('[data-school-class]');
  const existingStudent=form.querySelector('[data-existing-student]');
  const summary=root.querySelector('[data-registration-summary]');
  const loginPreview=form.querySelector('[data-generated-login]');
  const lastName=form.querySelector('input[name="last_name"]');
  const firstName=form.querySelector('input[name="first_name"]');
  const loginButton=form.querySelector('[data-regenerate-login]');
  const cyrillic={а:'a',б:'b',в:'v',г:'g',д:'d',е:'e',ё:'yo',ж:'zh',з:'z',и:'i',й:'i',к:'k',л:'l',м:'m',н:'n',о:'o',п:'p',р:'r',с:'s',т:'t',у:'u',ф:'f',х:'kh',ц:'ts',ч:'ch',ш:'sh',щ:'shch',ъ:'',ы:'y',ь:'',э:'e',ю:'yu',я:'ya',ә:'a',ғ:'gh',қ:'q',ң:'ng',ө:'o',ұ:'u',ү:'u',һ:'h',і:'i'};
  const loginPart=(value,limit)=>[...String(value||'').trim().toLowerCase()].map(ch=>Object.prototype.hasOwnProperty.call(cyrillic,ch)?cyrillic[ch]:ch).join('').normalize('NFKD').replace(/[^a-z0-9]/g,'').slice(0,limit)||'user';
  function numberSuffix(){
    if(window.crypto?.getRandomValues){const data=new Uint32Array(1);window.crypto.getRandomValues(data);return String(data[0]%10000).padStart(4,'0')}
    // The server securely generates the final login even without browser crypto.
    return '';
  }
  function refreshLogin(){
    if(!loginPreview)return;
    const family=lastName?.value.trim()||'';
    const given=firstName?.value.trim()||'';
    loginPreview.value=family&&given?loginPart(family,20)+'.'+loginPart(given,18)+'.'+numberSuffix():'';
  }
  [lastName,firstName].forEach(el=>el?.addEventListener('input',refreshLogin));
  loginButton?.addEventListener('click',refreshLogin);
  refreshLogin();
  const roleLabels={student:'Ученик · класс, группа и несколько кружков.',parent:'Родитель · привязка нескольких детей.',teacher:'Учитель · несколько кружков.',admin:'Администратор · без дополнительных полей.'};
  function currentRole(){return fixed?.value||radios.find(r=>r.checked)?.value||'student'}
  function updateCounts(){
    root.querySelectorAll('[data-select-group]').forEach(group=>{
      const name=group.getAttribute('data-select-group');
      const count=group.querySelectorAll('input[type="checkbox"]:checked').length;
      const label=root.querySelector('[data-count-for="'+name+'"]');
      if(label)label.textContent=count+' выбрано';
    });
  }
  function update(){
    const role=currentRole();
    cards.forEach(card=>{
      const show=card.getAttribute('data-role-panel')===role;
      card.hidden=!show;
      card.querySelectorAll('input,select,textarea').forEach(element=>{
        // Hidden role-specific controls must not be sent with a different role.
        element.disabled=!show;
      });
    });
    if(schoolClass){
      schoolClass.required=role==='student'&&(!existingStudent||existingStudent.value==='0');
    }
    if(summary)summary.textContent=roleLabels[role];
    updateCounts();
  }
  radios.forEach(r=>r.addEventListener('change',update));
  if(existingStudent)existingStudent.addEventListener('change',update);
  root.querySelectorAll('[data-select-group] input[type="checkbox"]').forEach(el=>el.addEventListener('change',updateCounts));
  root.querySelectorAll('[data-list-search]').forEach(search=>search.addEventListener('input',()=>{
    const group=root.querySelector('[data-select-group="'+search.getAttribute('data-list-search')+'"]');
    if(!group)return;
    const needle=search.value.trim().toLocaleLowerCase();
    group.querySelectorAll('.registration-option').forEach(option=>{option.hidden=!option.textContent.toLocaleLowerCase().includes(needle)});
  }));
  form.addEventListener('submit',()=>{
    // Prevent accidental double submission during slow deploy/network requests.
    const submit=form.querySelector('button[type="submit"]');
    if(submit){submit.disabled=true;submit.textContent='Сохранение…';}
  });
  update();
})();
