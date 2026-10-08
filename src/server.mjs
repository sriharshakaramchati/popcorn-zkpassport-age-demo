import http from 'node:http';
import {createRequire} from 'node:module';
import {randomBytes,randomUUID} from 'node:crypto';
import QRCode from 'qrcode';
import {chromium} from 'playwright-core';
import {verifySessionAttestation} from './attestation.mjs';
import {AgeFlow,SCOPE} from './flow.mjs';
const require=createRequire(import.meta.url),{ZKPassport}=require('@zkpassport/sdk');
const PORT=Number(process.env.PORT||3000),ORIGIN=process.env.PUBLIC_ORIGIN||`http://localhost:${PORT}`,DOMAIN=new URL(ORIGIN).hostname;
const API=(process.env.POPCORN_CONTROL_PLANE_URL||process.env.POPCORN_API_URL)?.replace(/\/$/,''),CLIENT=process.env.POPCORN_CLIENT_ID,SECRET=process.env.POPCORN_CLIENT_SECRET;
const VERIFIER=process.env.ATTESTATION_VERIFIER_URL,VERIFIER_TOKEN=process.env.ATTESTATION_VERIFIER_TOKEN;
const MODE=process.env.FLOW_MODE||'passport-only',KEY=process.env.CREDENTIAL_SIGNING_KEY||randomBytes(32).toString('hex');
if(!['passport-only','popcorn-connected','popcorn-attested'].includes(MODE))throw Error('Invalid FLOW_MODE');
if(ORIGIN.startsWith('http:')&&!['localhost','127.0.0.1'].includes(DOMAIN))throw Error('HTTPS required outside localhost');
if(!['localhost','127.0.0.1'].includes(DOMAIN)&&!process.env.CREDENTIAL_SIGNING_KEY)throw Error('Persistent signing key required for hosted service');
if(Buffer.byteLength(KEY)<32)throw Error('Signing key requires at least 32 bytes');
import {readFileSync} from 'node:fs';
const CLIENT_JS=readFileSync(new URL('./client/zk-browser.js',import.meta.url));
const zk=new ZKPassport(DOMAIN),deadline=()=>AbortSignal.timeout(20000);
async function createPopcorn(){
 if(!API||!CLIENT||!SECRET)throw Error('Popcorn deployment not configured');
 if(new URL(API).protocol!=='https:')throw Error('Popcorn API requires HTTPS');
 const r=await fetch(`${API}/v1/sessions`,{method:'POST',signal:deadline(),headers:{Authorization:`Bearer ${CLIENT}:${SECRET}`,'Content-Type':'application/json'},body:JSON.stringify({sessionId:`age-${randomUUID()}`,ttlSeconds:600,liveViewEncryption:'e2e',regions:[process.env.POPCORN_REGION||'asia-south1']})});
 if(!r.ok)throw Error('Popcorn session creation failed');const d=await r.json();
 if(!/^[A-Za-z0-9_-]{1,64}$/.test(d.sessionId)||!d.url||new URL(d.url).protocol!=='https:'||!Number.isFinite(Date.parse(d.expiresAt)))throw Error('Invalid Popcorn response');
 if(!d.cdpUrl||new URL(d.cdpUrl).protocol!=='wss:')throw Error('Invalid Popcorn CDP response');
 return {id:d.sessionId,liveViewUrl:d.url,cdpUrl:d.cdpUrl,expiresAt:d.expiresAt};
}
async function endSession(session){if(MODE==='passport-only'||!API)return;await fetch(`${API}/v1/session/${encodeURIComponent(session.id)}`,{method:'DELETE',signal:deadline(),headers:{Authorization:`Bearer ${CLIENT}:${SECRET}`}}).catch(()=>{})}
async function verifyAttestation(record){
 if(process.env.ATTESTATION_POLICY_PATH)return verifySessionAttestation({session:record.session,nonce:record.nonce,origin:ORIGIN});
 if(!VERIFIER||!VERIFIER_TOKEN||new URL(VERIFIER).protocol!=='https:')throw Error('Attestation verifier unavailable');
 const r=await fetch(VERIFIER,{method:'POST',signal:deadline(),headers:{'Content-Type':'application/json',Authorization:`Bearer ${VERIFIER_TOKEN}`},body:JSON.stringify({sessionId:record.session.id,nonce:record.nonce})});
 if(!r.ok)throw Error('Attestation verification failed');return r.json();
}
const flow=new AgeFlow({key:KEY,verifyProof:args=>zk.verify(args),verifyAttestation});
const owners=new Map(),rates=new Map();
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function headers(type){return {'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(), microphone=(), geolocation=()','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'self' 'unsafe-inline'; connect-src 'self' wss://bridge.zkpassport.id wss://*.zkpassport.id https://*.zkpassport.id; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"}}
function json(res,status,value){res.writeHead(status,headers('application/json'));res.end(JSON.stringify(value))}
function html(res,value){res.writeHead(200,headers('text/html; charset=utf-8'));res.end(value)}
function cookie(req){return (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('age_owner='))?.slice(10)}
function owner(req,res){let token=cookie(req);if(!token||!owners.has(token)){token=randomBytes(32).toString('hex');owners.set(token,{created:Date.now(),csrf:randomBytes(32).toString('hex')});res.setHeader('Set-Cookie',`age_owner=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800${ORIGIN.startsWith('https:')?'; Secure':''}`)}return {token,...owners.get(token)}}
async function body(req,max=4096){let d='';for await(const chunk of req){d+=chunk;if(d.length>max)throw Error('Payload too large')}return JSON.parse(d||'{}')}
function allowedPost(req,own){return req.headers.origin===ORIGIN&&req.headers['x-csrf-token']===own.csrf}
function rate(req){const k=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim(),now=Date.now();let r=rates.get(k);if(!r||now-r.start>60000){r={start:now,count:0};rates.set(k,r)}return ++r.count<=20}
const style=`body{font:16px system-ui;color:#251f21;background:#f4efec;margin:0;padding:24px}main{max-width:640px;background:white;margin:24px auto;padding:32px;border-radius:16px}h1{font-size:32px;letter-spacing:-.03em}p{line-height:1.6}button{background:#251f21;color:white;border:0;padding:14px 20px;border-radius:6px;cursor:pointer}img{display:block;max-width:100%;margin:20px 0}small{color:#585254}#status{padding:16px;background:#f4efec;border-radius:8px;margin:16px 0}a{color:#0d7061}code{overflow-wrap:anywhere}`;
function page(r,csrf){
 const intro=MODE==='passport-only'?'Real ZKPassport age-proof path. This mode binds the proof to this local demo session, not to a Popcorn browser.':MODE==='popcorn-connected'?'Popcorn connection configured; runtime acceptance testing is pending. Attestation verification is pending: this demo does not verify TEE execution.':'ZKPassport age proof bound to a Popcorn browser session. A verified attestation is required before the gate opens.';
 return `<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Popcorn x ZKPassport age demo</title><style>${style}</style><main><small>AGE-ONLY INTEGRATION TEST · ${esc(MODE)}</small><h1>Prove you are over 18.</h1><p>${intro}</p><p><small>No ID fields are requested. Passport/app proof generation is required. This is not a compliance claim.</small></p><div id="status">${r?'Scan with ZKPassport or open the app link.':'Start a fresh request.'}</div><div id="controls">${r?'<p><small>Preparing request...</small></p>':'<button id="start">Start age verification</button>'}</div></main>${r?'<script src="/zk-browser.js"></script>':''}<script>const binding=${JSON.stringify(r?.binding||null)},scope=${JSON.stringify(SCOPE)},id=${JSON.stringify(r?.id||null)},csrf=${JSON.stringify(csrf)},status=document.getElementById('status'),controls=document.getElementById('controls');async function post(url,value={}){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(value)});const d=await r.json();if(!r.ok)throw Error(d.error);return d}if(!id){document.getElementById('start').onclick=async e=>{e.target.disabled=true;try{const d=await post('/api/start');location.href='/gate/'+encodeURIComponent(d.id)}catch(e){status.textContent=e.message;document.getElementById('start').disabled=false}}}else{(async()=>{try{const {ZKPassport,QRCode}=window.AgeDemo,zk=new ZKPassport(location.hostname),q=await zk.request({name:'Popcorn x ZKPassport',purpose:'Prove over 18 for this demo session',scope,validity:600,devMode:false}),built=q.gte('age',18).bind('custom_data',binding).done();await post('/api/query',{id,query:built.query,requestId:built.requestId});const qr=document.createElement('img');qr.alt='ZKPassport age-proof request QR';qr.src=await QRCode.toDataURL(built.url,{width:256,margin:2});const a=document.createElement('a');a.href=built.url;a.rel='noreferrer';a.textContent='Open ZKPassport on this device';controls.replaceChildren(qr,a);built.onProofGenerated(()=>{status.textContent='Proof generated on your device. Sending it for verification...'});built.onSuccess(async({proofs,result})=>{try{await post('/api/proof',{id,proofs,result});return true}catch{return false}});built.onReject(()=>post('/api/event',{id,event:'rejected'}).catch(()=>{}));built.onError(()=>post('/api/event',{id,event:'error'}).catch(()=>{}))}catch(e){status.textContent='Could not start the ZKPassport request in this browser.';post('/api/event',{id,event:'error'}).catch(()=>{})}})();async function poll(){try{const r=await fetch('/api/status/'+encodeURIComponent(id)),d=await r.json();status.textContent=d.message||d.status;if(d.status==='ready'){controls.replaceChildren();const b=document.createElement('button');b.textContent='Redeem age proof and enter gate';b.onclick=async()=>{b.disabled=true;try{await post('/api/redeem',{id});location.href='/content/'+encodeURIComponent(id)}catch(e){status.textContent=e.message}};controls.append(b);return}if(['failed','expired','rejected','redeemed'].includes(d.status))return;setTimeout(poll,2000)}catch{status.textContent='Connection lost. Reload to retry.'}}poll()}</script></html>`;
}
const server=http.createServer(async(req,res)=>{
 try{
  const u=new URL(req.url,ORIGIN),own=owner(req,res);
  if(req.method==='POST'&&!allowedPost(req,own))return json(res,403,{error:'Origin or session check failed'});
  if(req.method==='GET'&&u.pathname==='/health')return json(res,200,{ok:true,mode:MODE});
  if(req.method==='GET'&&u.pathname==='/')return html(res,page(null,own.csrf));
  if(req.method==='POST'&&u.pathname==='/api/start'){
   if(MODE!=='passport-only'&&process.env.POPCORN_ALLOCATION_ENABLED!=='true')return json(res,503,{error:'Popcorn allocation is not enabled yet.'});
 if(!rate(req))return json(res,429,{error:'Too many requests. Try again in a minute.'});
   if([...flow.records.values()].filter(r=>r.owner===own.token&&!['expired','failed','rejected'].includes(r.status)).length>=2)return json(res,429,{error:'Two active requests already exist. Wait for expiry.'});
   const session=MODE==='passport-only'?{id:`local-${randomUUID()}`,expiresAt:new Date(Date.now()+600000).toISOString()}:await createPopcorn();
   const record=flow.create({owner:own.token,session,mode:MODE});
   return json(res,201,{id:record.id});
  }
  if(req.method==='POST'&&u.pathname==='/api/query'){
   const {id,query,requestId}=await body(req,65536);const r=flow.owned(id,own.token);if(!r||r.status!=='pending'||r.query)return json(res,409,{error:'Request not available'});
   flow.setQuery(r,query);r.requestId=String(requestId||'').slice(0,128);return json(res,200,{ok:true});
  }
  if(req.method==='POST'&&u.pathname==='/api/proof'){
   const {id,proofs,result}=await body(req,8388608);const r=flow.owned(id,own.token);if(!r||r.status!=='pending'||!r.query)return json(res,409,{error:'Request not available'});
   const ok=await flow.accept(r,{verified:true,result,proofs});return json(res,ok?200:422,{ok});
  }
  if(req.method==='POST'&&u.pathname==='/api/event'){
   const {id,event}=await body(req);const r=flow.owned(id,own.token);if(r&&r.status==='pending'){if(event==='rejected')r.status='rejected';else if(event==='error'){r.status='failed';r.error='ZKPassport request failed. Start over.'}}return json(res,200,{ok:true});
  }
  if(req.method==='GET'&&u.pathname==='/zk-browser.js'){res.writeHead(200,{...headers('text/javascript; charset=utf-8'),'Cache-Control':'public, max-age=300'});return res.end(CLIENT_JS)}
  if(req.method==='GET'&&u.pathname.startsWith('/gate/')){const r=flow.owned(u.pathname.slice(6),own.token);return r?html(res,page(r,own.csrf)):json(res,404,{error:'Not found'})}
  if(req.method==='GET'&&u.pathname.startsWith('/api/status/')){const r=flow.owned(u.pathname.slice(12),own.token);if(!r)return json(res,404,{error:'Not found'});return json(res,200,{status:r.status,message:r.error||({pending:'Waiting for a real ZKPassport proof.',ready:MODE==='passport-only'?'Age proof verified by the SDK. Local-session mode, no Popcorn attestation.':MODE==='popcorn-connected'?'Age proof verified. Popcorn session connected; attestation verification pending.':'Age proof and session attestation verified. Ready to redeem.'})[r.status]||r.status})}
  if(req.method==='POST'&&u.pathname==='/api/redeem'){
   const {id}=await body(req);const {record:r}=flow.redeem(id,own.token);
   if(MODE!=='passport-only'){
    r.contentToken=randomBytes(32).toString('hex');
    let browser;
    try{browser=await chromium.connectOverCDP(r.session.cdpUrl,{timeout:20000});const context=browser.contexts()[0];if(!context)throw Error('No browser context');const tab=context.pages()[0]||await context.newPage();await tab.goto(`${ORIGIN}/browser-content/${r.contentToken}`,{waitUntil:'domcontentloaded',timeout:20000});r.browserOpened=true;}
    catch{delete r.contentToken;r.status='failed';await endSession(r.session);throw Error('Browser navigation failed')}
    finally{if(browser)await browser.close().catch(()=>{})}
   }
   return json(res,200,{allowed:true,mode:MODE});
  }
  if(req.method==='GET'&&u.pathname.startsWith('/browser-content/')){
   const token=u.pathname.slice(17);const r=[...flow.records.values()].find(r=>r.contentToken===token&&r.status==='redeemed'&&Date.now()<r.credentialExpires);
   if(!r)return json(res,403,{error:'No valid redeemed proof'});
   return html(res,`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Age-gated content</title><style>${style}</style><main><small>POPCORN SESSION · ${esc(r.mode)}</small><h1>Age-gated content</h1><p>A real over-18 ZKPassport proof was verified server-side and redeemed for this browser session.</p><p>${r.mode==='popcorn-attested'?'Session attestation verified.':'Attestation verification pending. This demo does not verify TEE execution.'}</p><p>Access expires after five minutes or when the session ends.</p></main>`);
  }
  if(req.method==='GET'&&u.pathname.startsWith('/attestation/')){
   const r=[...flow.records.values()].find(r=>r.session.id===u.pathname.slice(13)&&r.owner===own.token&&r.mode==='popcorn-attested'&&r.status==='redeemed'&&Date.now()<r.credentialExpires);
   return r?json(res,200,{verified:true,sessionId:r.session.id,scope:'Google-signed platform claims, approved image identities and signatures checked against deployment policy.',expiresAt:new Date(r.credentialExpires).toISOString()}):json(res,403,{error:'No valid verified session'});
  }
  if(req.method==='GET'&&u.pathname.startsWith('/content/')){
   const r=flow.owned(u.pathname.slice(9),own.token);if(!r||r.status!=='redeemed'||Date.now()>=r.credentialExpires)return json(res,403,{error:'No valid redeemed proof'});
   return html(res,`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Age-gated demo</title><style>${style}</style><main><small>${esc(MODE)}</small><h1>Age-gated demo content</h1><p>Over-18 proof verified and redeemed for this session.</p><p>${MODE==='passport-only'?'This is a local age-gated page. No Popcorn browser or attestation is involved.':`<a rel="noreferrer" href="${esc(r.session.liveViewUrl)}">Open Popcorn encrypted LiveView</a><br>${MODE==='popcorn-attested'?`<a rel="noreferrer" href="${esc(r.verificationUrl)}">See session attestation verification</a>`:'<p>Attestation verification pending. This demo does not verify TEE execution.</p>'}`}</p><p>Access expires five minutes after verification, or earlier if the underlying session expires.</p></main>`)
  }
  return json(res,404,{error:'Not found'});
 }catch(err){console.error('ERR',req.method,req.url,err.message);const safe=['No redeemable credential','Credential expired or invalid'].includes(err.message)?err.message:'Request could not complete. Check deployment configuration or start a new request.';return json(res,503,{error:safe})}
});
server.listen(PORT,()=>console.log(`Age flow listening on ${ORIGIN} (${MODE})`));
setInterval(()=>{for(const r of flow.sweep()){if(r.requestId)zk.cancelRequest(r.requestId);endSession(r.session)}const now=Date.now();for(const [k,v]of owners)if(now-v.created>1800000)owners.delete(k);for(const [k,v]of rates)if(now-v.start>60000)rates.delete(k)},30000).unref();
process.on('SIGTERM',()=>{zk.clearAllRequests();server.close(()=>process.exit(0))});
