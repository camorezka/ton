/* Collectible Card interactions — release layer */
(function(){
  'use strict';

  function q(s){return document.querySelector(s)}
  function qa(s){return Array.from(document.querySelectorAll(s))}
  function safeIcons(){try{window.lucide?.createIcons?.()}catch(e){}}
  function currentCard(){try{return window.cvCurrent?.()||null}catch(e){return null}}
  function cards(){try{return window.cvReadCards?.()||[]}catch(e){return []}}
  function saveCards(a){try{window.cvWriteCards?.(a)}catch(e){}}
  function skinById(id){
    try{return window.CV_SKINS?.find(x=>x.id===id)||window.CV_SKINS?.[0]}catch(e){return null}
  }

  /* Add 18 deterministic SVG skins to the existing 60 photo skins. */
  function addSvgSkins(){
    try{
      if(!Array.isArray(window.CV_SKINS)) return;
      if(typeof window.makeSkinSvg!=='function') return;
      while(window.CV_SKINS.length<78){
        const n=window.CV_SKINS.length+1;
        window.CV_SKINS.push({id:'svg_'+n,name:'Studio '+String(n).padStart(2,'0'),url:window.makeSkinSvg(n+19)});
      }
    }catch(e){console.warn('skin extension failed',e)}
  }

  function logoSvg(){
    return '<svg viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="15" fill="#fff"/><path d="M10 16.2c0-4.2 2.7-7.3 6.6-7.3 2.1 0 4 .9 5.3 2.6" fill="none" stroke="#111318" stroke-width="2.8" stroke-linecap="round"/><path d="M10 16.2c0 4.2 2.7 7.3 6.6 7.3 2.1 0 4-.9 5.3-2.6" fill="none" stroke="#111318" stroke-width="2.8" stroke-linecap="round"/><path d="M10.5 16h11" stroke="#111318" stroke-width="2.8" stroke-linecap="round"/></svg>';
  }

  function paintCard(el,card){
    if(!el||!card)return;
    const skin=skinById(card.skin_id)||skinById('photo_1');
    if(!skin)return;
    el.querySelectorAll('.card-surface').forEach(s=>{
      s.style.backgroundImage='url("'+skin.url.replace(/"/g,'\\\"')+'")';
      s.style.backgroundSize='cover';
      s.style.backgroundPosition='center';
    });
    el.querySelectorAll('.card-logo').forEach(x=>x.innerHTML=logoSvg());
    const name='@'+String(card.card_username||'collector').replace(/^@/,'').slice(0,8);
    el.querySelectorAll('.card-username').forEach(x=>x.textContent=name);
  }

  function rebuildMainCard(){
    const stage=q('#cardStageMain');
    if(!stage)return;
    if(q('#card3d')){paintCard(q('#card3d'),currentCard());return}
    stage.innerHTML='<div id="card3d" class="card-3d card-cuboid" onclick="openFocusModal()"><div class="card-face card-front"><div class="card-surface"></div><div class="card-logo"></div><div class="card-username"></div></div><div class="card-face card-back"><div class="card-surface"></div></div><div class="card-edge card-left"></div><div class="card-edge card-right"></div><div class="card-edge card-top"></div><div class="card-edge card-bottom"></div></div>';
    paintCard(q('#card3d'),currentCard());
    safeIcons();
  }

  function focusMarkup(){
    let modal=q('#focusModal');if(!modal)return;
    let content=q('#ccFocusContent');
    if(content)return;
    content=document.createElement('div');
    content.id='ccFocusContent';
    content.className='cc-focus-content';
    content.innerHTML='<div class="cc-focus-title">Дизайн карточки</div><div id="ccSkinScroller" class="cc-skin-scroller"></div><div id="ccSaveState" class="cc-save-state"></div>';
    modal.appendChild(content);
    let cardWrap=q('.focus-card-wrap');
    if(cardWrap){
      cardWrap.classList.add('cc-focus-card');
      cardWrap.style.zIndex='4';
    }
  }

  function rebuildGallery(){
    addSvgSkins();
    focusMarkup();
    const box=q('#ccSkinScroller');if(!box)return;
    const c=currentCard();
    box.innerHTML='';
    (window.CV_SKINS||[]).forEach((skin,index)=>{
      const b=document.createElement('button');
      b.type='button';
      b.className='cc-skin'+(c&&c.skin_id===skin.id?' selected':'');
      b.dataset.skinId=skin.id;
      b.setAttribute('aria-label','Дизайн '+(index+1));
      const img=document.createElement('img');
      img.loading='lazy';img.decoding='async';img.alt='';img.src=skin.url;
      const n=document.createElement('span');n.className='cc-skin-index';n.textContent=String(index+1).padStart(2,'0');
      b.append(img,n);
      b.addEventListener('click',()=>chooseSkin(skin));
      box.appendChild(b);
    });
    const selected=box.querySelector('.selected');
    if(selected)setTimeout(()=>selected.scrollIntoView({inline:'center',block:'nearest',behavior:'smooth'}),80);
  }

  let saveTimer=0;
  function chooseSkin(skin){
    const c=currentCard();if(!c||!skin)return;
    c.skin_id=skin.id;
    saveCards(cards());
    window.state&&(window.state.currentSkin=skin.id);
    paintCard(q('#card3d'),c);
    paintCard(q('#focusCard3d'),c);
    qa('.cc-skin').forEach(x=>x.classList.toggle('selected',x.dataset.skinId===skin.id));
    const st=q('#ccSaveState');if(st)st.textContent='Сохранение…';
    clearTimeout(saveTimer);
    saveTimer=setTimeout(async()=>{
      try{
        if(c.backendId&&window.apiPost){
          const d=await window.apiPost('update_card_settings',{item_id:c.backendId,skin_id:c.skin_id});
          if(!d.ok)throw new Error(d.error||'Не удалось сохранить');
        }
        if(st)st.textContent='Сохранено';
        setTimeout(()=>{if(st)st.textContent=''},1000);
      }catch(e){
        if(st)st.textContent='Не удалось сохранить';
      }
    },120);
    try{window.haptic?.('light')}catch(e){}
  }

  /* Override the broken legacy visual function with the same stable renderer. */
  window.applyCvCardVisual=function(card){
    if(!card)return;
    paintCard(q('#card3d'),card);
    paintCard(q('#focusCard3d'),card);
    const name='@'+String(card.card_username||'collector').replace(/^@/,'').slice(0,8);
    const main=q('#cardUsernameMain'),focus=q('#focusHolderName');
    if(main)main.textContent=name;
    if(focus)focus.textContent=name;
  };

  /* The profile should never render a card. */
  window.updateProfile=function(){
    const u=window.state?.tgUser||{};
    const name=[u.first_name,u.last_name].filter(Boolean).join(' ')||'Пользователь';
    const username=u.username?'@'+u.username:'@guest';
    const set=(id,v)=>{const e=q('#'+id);if(e)e.textContent=v};
    set('profName',name);set('profUsername',username);set('profCards',cards().length);
    const img=q('#profAvatar'),icon=q('#profAvatarIcon');
    if(img&&icon){
      if(u.photo_url){img.src=u.photo_url;img.classList.remove('hidden');icon.classList.add('hidden')}
      else{img.classList.add('hidden');icon.classList.remove('hidden')}
    }
  };

  /* Rebuild the focus screen instead of leaving a half-empty modal. */
  const oldOpen=window.openFocusModal;
  window.openFocusModal=function(){
    focusMarkup();
    const m=q('#focusModal');if(!m)return;
    m.classList.add('open');
    rebuildGallery();
    window.applyCvCardVisual(currentCard());
    try{window.tg?.BackButton?.show?.();window.tg?.BackButton?.offClick?.(window.closeFocusModal);window.tg?.BackButton?.onClick?.(window.closeFocusModal)}catch(e){}
    try{window.haptic?.('medium')}catch(e){}
  };

  window.closeFocusModal=function(){
    const m=q('#focusModal');if(m)m.classList.remove('open');
    try{window.tg?.BackButton?.hide?.();window.tg?.BackButton?.offClick?.(window.closeFocusModal)}catch(e){}
    try{window.haptic?.('light')}catch(e){}
  };

  /* No username on the home header. */
  const title=q('#greetName');if(title)title.textContent='';

  /* Smooth nav indicator without adding another DOM node. */
  function navIndicator(){
    const nav=q('#bottomNav');if(!nav)return;
    const active=q('#bottomNav .nav-btn.active');if(!active)return;
    const first=q('#bottomNav .nav-btn:first-child');if(!first)return;
    const shift=active===first?'0%':'100%';
    nav.style.setProperty('--nav-shift',shift);
  }
  const oldSwitch=window.switchTab;
  if(typeof oldSwitch==='function'){
    window.switchTab=function(tab){
      oldSwitch(tab);
      requestAnimationFrame(navIndicator);
      setTimeout(navIndicator,360);
    };
  }

  /* Do not let the old profile CSS reveal the collection underneath. */
  document.addEventListener('click',()=>setTimeout(()=>{
    const p=q('#screen-profile'),c=q('#screen-collection');
    if(p?.classList.contains('hidden'))p.style.removeProperty('display');
    if(c?.classList.contains('hidden'))c.style.removeProperty('display');
    navIndicator();
  },0),{passive:true});

  /* Re-apply after the app's asynchronous card bootstrap. */
  const boot=setInterval(()=>{
    const c=currentCard();
    if(c){
      rebuildMainCard();
      if(q('#focusModal')?.classList.contains('open'))rebuildGallery();
      updateProfile();
    }
    navIndicator();
  },900);
  setTimeout(()=>clearInterval(boot),15000);

  addSvgSkins();
  safeIcons();
  setTimeout(()=>{rebuildMainCard();updateProfile();navIndicator()},250);
})();