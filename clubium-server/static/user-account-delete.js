/* ÜiirmeHub — account deletion controls, role access enforced on server. */
(()=>{'use strict';
  const grid=document.querySelector('#usersTable');
  if(grid){
    const checks=[...grid.querySelectorAll('[data-account-check]')];
    const all=grid.querySelector('[data-account-select-all]');
    const bulk=document.querySelector('[data-bulk-delete-form]');
    const bulkBtn=document.querySelector('[data-bulk-delete-button]');
    const number=document.querySelector('[data-bulk-count]');
    function update(){
      const selected=checks.filter(el=>el.checked).length;
      if(number)number.textContent=String(selected);
      if(bulkBtn)bulkBtn.disabled=selected===0;
      const visible=checks.filter(el=>el.closest('tr')?.style.display!=='none');
      const selectedVisible=visible.filter(el=>el.checked).length;
      if(all){all.checked=visible.length>0&&selectedVisible===visible.length;
        all.indeterminate=selectedVisible>0&&selectedVisible<visible.length;}
    }
    all?.addEventListener('change',()=>{
      checks.filter(el=>el.closest('tr')?.style.display!=='none').forEach(el=>el.checked=all.checked);
      update();
    });
    checks.forEach(el=>el.addEventListener('change',update));
    bulk?.addEventListener('submit',event=>{
      const count=checks.filter(el=>el.checked).length;
      if(!count||count>100){event.preventDefault();return;}
      if(!window.confirm(`Безвозвратно удалить ${count} аккаунт(ов)? Доступ и личные сообщения будут удалены, но учебные карточки и кружки сохранятся.`))event.preventDefault();
    });
    grid.querySelectorAll('[data-user-delete-form]').forEach(form=>{
      form.addEventListener('submit',event=>{
        if(!window.confirm(`Удалить аккаунт @${form.dataset.username||'пользователь'}? Его доступ и личные сообщения будут удалены.`))event.preventDefault();
      });
    });
    grid.closest('.panel')?.querySelector('.search-input')?.addEventListener('input',()=>setTimeout(update,0));
    update();
  }
  // Existing full reset keeps its password check; copying avoids typos in Russian phrases.
  document.querySelectorAll('[data-copy-reset-phrase]').forEach(button=>{
    button.addEventListener('click',()=>{
      const input=button.closest('form')?.querySelector('input[name="confirm"]');
      if(input){input.value=button.dataset.copyResetPhrase||'';input.focus();}
    });
  });
})();
