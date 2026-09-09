import {processPhoto,encryptPhoto} from './image.js';
import './auth.js';
const status=document.querySelector('#status'), input=document.querySelector('#file'), progress=document.querySelector('progress');
let busy=false;
async function upload(file) {
  if(!file || busy) return;
  busy=true; input.disabled=true; document.querySelector('#result').hidden=true;
  try {
    status.textContent='Preparing photo…'; progress.hidden=false; progress.removeAttribute('value');
    const photo=await processPhoto(file);
    const {key,payload}=await encryptPhoto(photo);
    const session=await fetch('/drop/api/session');
    if(!session.ok) throw Error('Open your private invite link again.');
    const {csrf}=await session.json();
    status.textContent='Uploading…';
    const result=await new Promise((resolve,reject)=>{
      const xhr=new XMLHttpRequest(); xhr.open('POST','/drop/api/photos'); xhr.timeout=60000;
      xhr.setRequestHeader('Content-Type','application/octet-stream'); xhr.setRequestHeader('X-CSRF-Token',csrf);
      xhr.upload.onprogress=e=>{ if(e.lengthComputable) { progress.max=e.total; progress.value=e.loaded; } };
      xhr.onerror=xhr.ontimeout=()=>reject(Error('Upload failed. Please try again.'));
      xhr.onload=()=>{ let data; try { data=JSON.parse(xhr.responseText); } catch { reject(Error('Upload failed. Please try again.')); return; }
        xhr.status===201 ? resolve(data) : reject(Error(data.error || 'Upload failed.')); };
      xhr.send(payload);
    });
    const url=location.origin+'/drop/p/'+result.id+'#'+key;
    const link=document.querySelector('#share'); link.href=url; link.textContent=url;
    document.querySelector('#result').hidden=false; status.textContent='Photo ready to share.';
  } catch(error) { status.textContent=error.message; }
  finally {busy=false; input.disabled=false; progress.hidden=true; input.value='';}
}
input.addEventListener('change',()=>upload(input.files[0]));
const zone=document.querySelector('#zone');
zone.addEventListener('dragover',e=>{e.preventDefault();});
zone.addEventListener('drop',e=>{e.preventDefault();upload(e.dataTransfer.files[0]);});
document.querySelector('#copy').addEventListener('click',async()=>{
  try {await navigator.clipboard.writeText(document.querySelector('#share').href); status.textContent='Link copied.';}
  catch {status.textContent='Select and copy the link above.';}
});
