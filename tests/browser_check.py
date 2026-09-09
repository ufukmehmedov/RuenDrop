"""Real browser checks; pass an invite through a private file, never CLI arguments.
RUENDROP_TEST_URL defaults to local test service. No secret URLs are printed.
"""
import base64
import io
import json
import os
from pathlib import Path
from PIL import Image
from playwright.sync_api import sync_playwright, expect

def run():
    origin=os.environ.get('RUENDROP_TEST_URL','http://localhost:8787')
    invite=Path(os.environ['RUENDROP_TEST_INVITE']).read_text().strip()
    token=invite.split('#')[-1]
    im=Image.new('RGB',(3000,1500),'#39795a')
    exif=Image.Exif(); exif[274]=6; exif[270]='PRIVATE_METADATA_SENTINEL'; exif[34853]={1:'N',2:(42.0,0.0,0.0),3:'E',4:(23.0,0.0,0.0)}
    buf=io.BytesIO(); im.save(buf,format='JPEG',exif=exif)
    source=buf.getvalue()
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        ctx=browser.new_context()
        page=ctx.new_page()
        errors=[]; requests=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        def record(req):
            requests.append((req.url, req.post_data_buffer or b'', req.all_headers()))
        page.on('request',record)
        page.goto(origin+'/drop/')
        assert page.locator('#file').count()==0
        page.goto(origin+'/drop/#invalid')
        expect(page.locator('#status')).to_contain_text('invalid')
        page.goto(origin+'/drop/#'+token)
        page.wait_for_selector('#file',state='attached')
        assert page.url==origin+'/drop/'
        page.locator('#file').set_input_files({'name':'fake.jpg','mimeType':'image/jpeg','buffer':b'not an image'})
        expect(page.locator('#status')).to_contain_text('valid JPEG')
        page.locator('#file').set_input_files({'name':'huge.jpg','mimeType':'image/jpeg','buffer':b'x'*(10*1024*1024+1)})
        expect(page.locator('#status')).to_contain_text('10 MB')
        # Plausible PNG header with absurd dimensions must fail before decoding.
        bomb=b'\x89PNG\r\n\x1a\n'+b'\x00\x00\x00\rIHDR'+(100000).to_bytes(4,'big')*2
        page.locator('#file').set_input_files({'name':'bomb.png','mimeType':'image/png','buffer':bomb})
        expect(page.locator('#status')).to_contain_text('dimensions')
        page.locator('#file').set_input_files({'name':'photo.jpg','mimeType':'image/jpeg','buffer':source})
        page.wait_for_selector('#result:not([hidden])',timeout=60000)
        link=page.locator('#share').get_attribute('href')
        key=link.split('#')[1]
        photo_id=link.split('/p/')[1].split('#')[0]
        upload=ctx.request.get(origin+'/drop/api/photos/'+photo_id).body()
        assert upload.startswith(b'RD01') and source not in upload
        assert base64.urlsafe_b64decode(key+'=') not in upload
        try: Image.open(io.BytesIO(upload)); raise AssertionError('Plaintext stored')
        except Image.UnidentifiedImageError: pass
        recipient=browser.new_context(); view=recipient.new_page()
        view.on('request',record)
        view.goto(link)
        view.wait_for_selector('#photo:not([hidden])')
        expect(view.locator('#photo')).to_be_visible()
        size=view.locator('#photo').evaluate('(img)=>[img.naturalWidth,img.naturalHeight]')
        assert size==[1000,2000],size
        plain=view.evaluate('''async ({id,key})=>{
          const {decryptPhoto}=await import('/drop/assets/image.js');
          const r=await fetch('/drop/api/photos/'+id);
          const blob=await decryptPhoto(await r.arrayBuffer(),key);
          return Array.from(new Uint8Array(await blob.arrayBuffer()));
        }''',{'id':photo_id,'key':key})
        image=Image.open(io.BytesIO(bytes(plain)))
        assert not image.getexif() and b'PRIVATE_METADATA_SENTINEL' not in bytes(plain)
        assert len(plain)<len(source)
        view.goto('about:blank'); view.goto(link.split('#')[0]); expect(view.locator('#status')).to_contain_text('missing')
        view.goto('about:blank'); view.goto(link.split('#')[0]+'#'+'A'*43); expect(view.locator('#status')).to_contain_text('Unable')
        for url,body,headers in requests:
            assert key not in url and key.encode() not in body and key not in json.dumps(headers)
            assert token not in url and token not in json.dumps(headers)
            assert not headers.get('referer')
        assert not errors,errors
        if os.environ.get('RUENDROP_TEST_RESULT'):
            path=Path(os.environ['RUENDROP_TEST_RESULT'])
            path.write_text(json.dumps({'link':link,'cookies':ctx.cookies(),'ciphertext':base64.b64encode(upload).decode()})); path.chmod(0o600)
        browser.close()
    print('PASS: browser authorization, invalid invite, photo-only, size/pixel limits, orientation, resize, metadata removal, E2EE, private-context viewing, missing/wrong keys, no secret in requests/headers.')

if __name__=='__main__': run()
