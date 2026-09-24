// Optional DOM interaction test, requires jsdom. Not a rendered browser test.
const fs=require('node:fs');const assert=require('node:assert/strict');const path=require('node:path');
const {JSDOM}=require('jsdom');
(async()=>{
 const base=process.env.DACONIC_TEST_URL||'http://127.0.0.1:8080';
 const dir=path.join(__dirname,'../src/daconic_governance/dashboard');
 const dom=new JSDOM(fs.readFileSync(path.join(dir,'index.html'),'utf8'),{url:base,runScripts:'outside-only'});
 const w=dom.window;w.fetch=(url,options)=>fetch(base+url,options);
 w.HTMLDialogElement.prototype.showModal=function(){this.open=true};w.HTMLDialogElement.prototype.close=function(){this.open=false};
 let copied='';Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async v=>{copied=v}}});
 w.eval(fs.readFileSync(path.join(dir,'app.js'),'utf8'));
 const el=id=>w.document.getElementById(id);
 el('token').value=process.env.DACONIC_API_TOKEN;el('connect').click();
 async function until(predicate){for(let n=0;n<100;n++){if(predicate())return;await new Promise(r=>setTimeout(r,30));}throw Error('Timed out');}
 await until(()=>el('rows').querySelectorAll('button').length===5);
 assert.equal(el('cards').children.length,5);assert.equal(el('cards').children[0].querySelector('strong').textContent,'5');
 el('status').value='VIOLATION';el('status').dispatchEvent(new w.Event('input'));assert.equal(el('rows').querySelectorAll('button').length,2);
 el('status').value='';el('status').dispatchEvent(new w.Event('input'));
 el('rows').querySelector('button').click();assert.equal(el('detail').open,true);
 assert.ok(el('comparison').textContent.includes('with_processing'));
 el('copy').click();await until(()=>copied.length>0);assert.ok(!copied.includes('alice@example.test'));assert.ok(copied.includes('[WITHHELD]'));
 el('close').click();assert.equal(el('detail').open,false);
 el('verify').click();await until(()=>!el('verify').disabled);assert.ok(el('integrity').textContent.includes('PASS'));
 el('search').value='impossible-search';el('search').dispatchEvent(new w.Event('input'));assert.ok(el('rows').textContent.includes('No matching observations'));
 el('search').value='';el('refresh').click();await until(()=>el('rows').querySelectorAll('button').length===5);assert.ok(el('integrity').textContent.includes('Not run'));
 console.log('PASS: DOM connect, summary, filters, detail, safe copy, comparison, live verification, empty state, refresh');dom.window.close();
})().catch(error=>{console.error(error);process.exitCode=1});
