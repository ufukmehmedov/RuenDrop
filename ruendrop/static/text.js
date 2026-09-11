const $ = s => document.querySelector(s);
const status = message => { $('#status').textContent = message; };
const encode = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
const decode = value => Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')+'='), c=>c.charCodeAt(0));
const utf8 = new TextEncoder();
async function api(path, options={}) {
  const response = await fetch('/text/api/'+path, {credentials:'same-origin',cache:'no-store',...options});
  if (!response.ok) throw Error(response.status === 404 ? 'Text expired, already opened, or revoked.' : response.status === 429 ? 'Please try again later.' : 'Request failed. Check your invite or try again.');
  return response;
}
async function authorize() {
  if (location.pathname !== '/text/' || !location.hash) return;
  const token = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  try {
    await api('auth', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
    location.replace('/text/');
  } catch { status('Invite link is invalid or unavailable.'); }
}
window.addEventListener('hashchange', authorize);
authorize();
if ($('#create')) $('#create').addEventListener('click', async () => {
  $('#create').disabled = true;
  $('#result').hidden = true;
  $('#share').value = '';
  try {
    const text = $('#message').value;
    if (!text.length) throw Error('Enter some text first.');
    if (utf8.encode(text).length > 1024*1024) throw Error('Text is too long (1 MiB maximum encrypted content).');
    const mode = $('#mode').value;
    const receipt = encode(crypto.getRandomValues(new Uint8Array(32)));
    const plain = utf8.encode(JSON.stringify({version:1,text,mode,receipt}));
    if (plain.length+32 > 1024*1024) throw Error('Text is too long (1 MiB maximum encrypted content).');
    const key = await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const magic = utf8.encode('RT01');
    const encrypted = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:magic},key,plain);
    const receiptHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',utf8.encode(receipt))),b=>b.toString(16).padStart(2,'0')).join('');
    const session = await (await api('session')).json();
    const result = await (await api('texts',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-CSRF-Token':session.csrf,'X-Text-Mode':mode,'X-Text-Receipt':receiptHash},body:new Blob([magic,iv,encrypted])})).json();
    const fragment = encode(new Uint8Array(await crypto.subtle.exportKey('raw',key)));
    $('#share').value = location.origin+'/text/t/'+result.id+'#'+fragment;
    $('#result').hidden = false;
    status('Secure link created. Anyone with the complete link can read it.');
  } catch(error) { status(error.message); }
  finally { $('#create').disabled = false; }
});
if ($('#copy')) $('#copy').addEventListener('click',async()=>{
  try { await navigator.clipboard.writeText($('#share').value); status('Link copied.'); }
  catch { $('#share').select(); status('Select and copy the link.'); }
});
if ($('#open')) $('#open').addEventListener('click',async()=>{
  $('#open').disabled = true;
  try {
    const fragment = location.hash.slice(1);
    if (!/^[A-Za-z0-9_-]{43}$/.test(fragment)) throw Error('Encryption key is missing or invalid. Use the complete share link.');
    const key = await crypto.subtle.importKey('raw',decode(fragment),{name:'AES-GCM'},false,['decrypt']);
    const id = location.pathname.split('/').pop();
    const bytes = new Uint8Array(await (await api('texts/'+id)).arrayBuffer());
    if (bytes.length<33 || new TextDecoder().decode(bytes.slice(0,4))!=='RT01') throw Error('Invalid encrypted text.');
    let envelope;
    try {
      const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(4,16),additionalData:bytes.slice(0,4)},key,bytes.slice(16));
      envelope = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));
      if (envelope.version!==1 || typeof envelope.text!=='string' || !['burn','24h'].includes(envelope.mode) || !/^[A-Za-z0-9_-]{43}$/.test(envelope.receipt)) throw Error();
    } catch { throw Error('Unable to decrypt. The key is wrong or the text was damaged.'); }
    // Do not display until the atomic receipt acknowledgment succeeds.
    await api('texts/'+id+'/opened',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({receipt:envelope.receipt})});
    $('#plaintext').value = envelope.text;
    $('#plaintext').hidden = false;
    $('#plain-label').hidden = false;
    $('#open').hidden = true;
    status(envelope.mode==='burn' ? 'Opened. Server ciphertext has been deleted; this link cannot be opened again.' : 'Decrypted. This link expires 24 hours after creation.');
  } catch(error) { status(error.message); $('#open').disabled = false; }
});
window.addEventListener('pagehide',()=>{ if ($('#plaintext')) { $('#plaintext').value=''; $('#plaintext').hidden=true; } });
window.addEventListener('pageshow',event=>{ if(event.persisted) location.reload(); });
