import {decryptPhoto} from './image.js';
const secret=location.hash.slice(1), status=document.querySelector('#status');
// Keep the fragment for reload/copy; fragments never travel in HTTP requests.
if(!secret) status.textContent='The decryption key is missing. Open the complete share link.';
else {
  try {
    const id=location.pathname.split('/').pop();
    const response=await fetch('/drop/api/photos/'+encodeURIComponent(id),{credentials:'omit'});
    if(!response.ok) throw Error(response.status===404?'Photo expired or not found.':'Photo is temporarily unavailable.');
    const blob=await decryptPhoto(await response.arrayBuffer(),secret);
    const url=URL.createObjectURL(blob), img=document.querySelector('#photo');
    img.onload=()=>URL.revokeObjectURL(url);
    img.src=url; img.hidden=false; status.textContent='';
  } catch(error) { status.textContent=error.message.startsWith('Photo ')?error.message:'Unable to open photo. The link may be incomplete or damaged.'; }
}
