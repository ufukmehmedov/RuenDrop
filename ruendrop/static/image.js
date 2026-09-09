export const MAX_INPUT = 10 * 1024 * 1024;
const MAX_PIXELS = 40_000_000;
function check(w,h) {
  if (!w || !h || w*h > MAX_PIXELS || Math.max(w,h)>32768) throw Error('Photo dimensions are too large.');
  return [w,h];
}
// Read dimensions before invoking a decoder; never trust the filename or MIME.
export function dimensions(buffer) {
  const b=new Uint8Array(buffer), v=new DataView(buffer);
  if (b.length>=24 && v.getUint32(0)===0x89504e47 && v.getUint32(4)===0x0d0a1a0a && v.getUint32(12)===0x49484452)
    return check(v.getUint32(16),v.getUint32(20));
  if (b[0]===255 && b[1]===216) {
    let p=2;
    while(p+4<=b.length) {
      if(b[p++]!==255) break;
      while(b[p]===255) p++;
      const marker=b[p++];
      if(marker===217 || marker===218) break;
      if(marker===1 || (marker>=208 && marker<=215)) continue;
      const n=v.getUint16(p);
      if(n<2 || p+n>b.length) break;
      if([192,193,194].includes(marker) && n>=8) return check(v.getUint16(p+5),v.getUint16(p+3));
      p+=n;
    }
  }
  if(b.length>=30 && v.getUint32(0)===0x52494646 && v.getUint32(8)===0x57454250) {
    const tag=v.getUint32(12);
    if(tag===0x56503858) {
      if(b[20]&2) throw Error('Please select a still photo.');
      return check(1+b[24]+(b[25]<<8)+(b[26]<<16),1+b[27]+(b[28]<<8)+(b[29]<<16));
    }
    if(tag===0x56503820 && b[23]===0x9d && b[24]===1 && b[25]===0x2a)
      return check(v.getUint16(26,true)&16383,v.getUint16(28,true)&16383);
    if(tag===0x5650384c && b[20]===0x2f)
      return check(1+b[21]+((b[22]&63)<<8),1+(b[22]>>6)+(b[23]<<2)+((b[24]&15)<<10));
  }
  throw Error('Select a valid JPEG, PNG or WebP photo.');
}
export async function processPhoto(file) {
  if(file.size>MAX_INPUT) throw Error('Choose a photo smaller than 10 MB.');
  dimensions(await file.arrayBuffer());
  let bitmap;
  try { bitmap=await createImageBitmap(file,{imageOrientation:'from-image'}); }
  catch { throw Error('This file could not be decoded as a photo.'); }
  try {
    check(bitmap.width,bitmap.height);
    const scale=Math.min(1,2000/Math.max(bitmap.width,bitmap.height));
    const canvas=document.createElement('canvas');
    canvas.width=Math.max(1,Math.round(bitmap.width*scale));
    canvas.height=Math.max(1,Math.round(bitmap.height*scale));
    const ctx=canvas.getContext('2d',{alpha:false});
    ctx.fillStyle='#fff'; ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.drawImage(bitmap,0,0,canvas.width,canvas.height);
    const output=await new Promise(resolve=>canvas.toBlob(resolve,'image/jpeg',0.82));
    if(!output || output.size>6*1024*1024-32) throw Error('Photo is too large after processing.');
    return output;
  } finally { bitmap.close(); }
}
export function encode(bytes) { return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=',''); }
export function decode(text) {
  if(!/^[A-Za-z0-9_-]{43}$/.test(text)) throw Error('Invalid key.');
  return Uint8Array.from(atob(text.replaceAll('-','+').replaceAll('_','/')+'='),c=>c.charCodeAt(0));
}
export async function encryptPhoto(blob) {
  const key=crypto.getRandomValues(new Uint8Array(32));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt']);
  const header=new TextEncoder().encode('RD01');
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:header},cryptoKey,await blob.arrayBuffer());
  return {key:encode(key),payload:new Blob([header,iv,ciphertext],{type:'application/octet-stream'})};
}
async function decryptPayload(buffer,secret) {
  const bytes=new Uint8Array(buffer);
  if(bytes.length<33 || new TextDecoder().decode(bytes.slice(0,4))!=='RD01') throw Error('Invalid photo.');
  const key=await crypto.subtle.importKey('raw',decode(secret),'AES-GCM',false,['decrypt']);
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(4,16),additionalData:bytes.slice(0,4)},key,bytes.slice(16));
  return plain;
}
function checkedPhoto(plain) {
  const [w,h]=dimensions(plain);
  if(Math.max(w,h)>2000) throw Error('Invalid photo dimensions.');
  return new Blob([plain],{type:'image/jpeg'});
}

export const MAX_PHOTOS = 10;
const MAX_DROP = 20 * 1024 * 1024;
// The entire length-delimited gallery is authenticated and encrypted, including its count.
export async function encryptDrop(files, onProgress=()=>{}) {
  if(!files.length || files.length>MAX_PHOTOS) throw Error('Select between 1 and 10 photos.');
  const parts=[new TextEncoder().encode('RDB1'),new Uint8Array([files.length])];
  let size=5;
  for(let i=0;i<files.length;i++) {
    onProgress(i+1,files.length);
    const photo=await processPhoto(files[i]);
    size+=4+photo.size;
    if(size+32>MAX_DROP) throw Error('Together these photos exceed the 20 MiB drop limit. Select fewer photos.');
    const length=new Uint8Array(4); new DataView(length.buffer).setUint32(0,photo.size);
    parts.push(length,photo);
  }
  return encryptPhoto(new Blob(parts));
}
export async function decryptDrop(buffer,secret) {
  if(buffer.byteLength>MAX_DROP) throw Error('Invalid drop size.');
  const plain=await decryptPayload(buffer,secret), bytes=new Uint8Array(plain);
  // Legacy RD01 drops contain a single JPEG directly.
  if(new TextDecoder().decode(bytes.slice(0,4))!=='RDB1') return [checkedPhoto(plain)];
  const count=bytes[4], photos=[], view=new DataView(plain);
  if(!count || count>MAX_PHOTOS) throw Error('Invalid gallery.');
  let offset=5;
  for(let i=0;i<count;i++) {
    if(offset+4>bytes.length) throw Error('Invalid gallery.');
    const length=view.getUint32(offset); offset+=4;
    if(!length || offset+length>bytes.length) throw Error('Invalid gallery.');
    photos.push(checkedPhoto(plain.slice(offset,offset+length))); offset+=length;
  }
  if(offset!==bytes.length) throw Error('Invalid gallery.');
  return photos;
}
export async function decryptPhoto(buffer,secret) {
  const photos=await decryptDrop(buffer,secret);
  if(photos.length!==1) throw Error('This drop contains multiple photos.');
  return photos[0];
}
