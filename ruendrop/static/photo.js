import {decryptDrop} from './image.js';
const secret=location.hash.slice(1), status=document.querySelector('#status');
// Fragments never travel in HTTP requests.
if(!secret) status.textContent='The decryption key is missing. Open the complete share link.';
else {
  try {
    const id=location.pathname.split('/').pop();
    const response=await fetch('/drop/api/photos/'+encodeURIComponent(id),{credentials:'omit'});
    if(!response.ok) throw Error(response.status===404?'Photo expired or not found.':'Photo is temporarily unavailable.');
    const photos=await decryptDrop(await response.arrayBuffer(),secret);
    const gallery=document.querySelector('#gallery');
    for(const [i,blob] of photos.entries()) {
      const img=document.createElement('img'), url=URL.createObjectURL(blob);
      img.alt=`Shared photo ${i+1} of ${photos.length}`;
      if(i===0) img.id='photo';
      img.onload=img.onerror=()=>URL.revokeObjectURL(url);
      img.src=url; gallery.append(img);
    }
    status.textContent=`${photos.length} ${photos.length===1?'photo':'photos'} · This drop expires 24 hours after upload.`;
  } catch(error) { status.textContent=error.message.startsWith('Photo ')?error.message:'Unable to open drop. The link may be incomplete or damaged.'; }
}
