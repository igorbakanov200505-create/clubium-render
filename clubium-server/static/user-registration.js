/* Only activates on admin account registration/edit forms. */
(function(){
  'use strict';
  const root=document.querySelector('[data-user-registration]');
  if(!root)return;
  const form=root.querySelector('#registrationForm');
  const cards=[...root.querySelectorAll('[data-role-panel]')];
  const radios=[...root.querySelectorAll('input[type="radio"][name="role"]')];
  const fixed=form.querySelector('input[type="hidden"][name="role"]');
  const schoolClass=form.querySelector('[data-school-class]');
  const existingStudent=form.querySelector('[data-existing-student]');
  const summary=root.querySelector('[data-registration-summary]');
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
