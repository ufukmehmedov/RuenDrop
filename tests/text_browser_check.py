"""Real Web Crypto and UTF-8 checks, local or HTTPS. Never print secret links."""
import base64
import json
import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

SAMPLE='Turkish: ç ğ ı İ ö ş ü Ç Ğ Ö Ş Ü\nBulgarian: А Б В Г Д Е Ж З И Й К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ъ Ь Ю Я\nEnglish: private text <script>alert(1)</script>\n\nPreserved lines ✅'

def run():
    origin=os.environ.get('RUENDROP_TEST_URL','http://localhost:8787')
    token=Path(os.environ['RUENDROP_TEST_INVITE']).read_text().strip().split('#')[-1]
    records=[]; keys=[]; ids=[]; errors=[]
    # Each no-store page loads shared branding assets. Pace synthetic navigation
    # to respect production's existing 5 requests/second nginx limit.
    def navigate(view, url):
        if origin.startswith('https:'): time.sleep(2)
        view.goto(url)
    with sync_playwright() as p:
        browser=p.chromium.launch()
        creator=browser.new_context(viewport={'width':390,'height':844})
        page=creator.new_page()
        def record(req):
            records.append((req.url,req.post_data_buffer or b'',req.all_headers()))
        page.on('request',record); page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(origin+'/text/')
        assert page.locator('#message').count()==0
        page.goto(origin+'/text/#'+token)
        expect(page.locator('#message')).to_be_visible()
        assert page.url==origin+'/text/'
        assert page.locator('#message').get_attribute('spellcheck')=='true'
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        assert page.locator('.brand').evaluate('(e)=>e.complete && e.naturalWidth===600')
        assert page.locator('.brand').get_attribute('src')=='/drop/assets/logo.png'
        print('PASS: invite authentication and mobile layout',flush=True)
        for mode,message in [('24h',SAMPLE*600),('burn',SAMPLE)]:
            print('Testing '+mode,flush=True)
            page.locator('#message').fill(message)
            page.locator('#mode').select_option(mode)
            page.locator('#create').click()
            expect(page.locator('#result')).to_be_visible(timeout=30000)
            link=page.locator('#share').input_value()
            key=link.split('#')[1]; keys.append(key)
            tid=link.split('/t/')[1].split('#')[0]; ids.append(tid)
            response=creator.request.get(origin+'/text/api/texts/'+tid)
            assert response.ok
            cipher=response.body()
            assert cipher.startswith(b'RT01') and SAMPLE.encode() not in cipher
            assert base64.urlsafe_b64decode(key+'=') not in cipher
            reader=browser.new_context(viewport={'width':390,'height':844}); view=reader.new_page()
            view.on('request',record); view.on('pageerror',lambda e:errors.append(str(e)))
            navigate(view, link.split('#')[0])
            expect(view.locator('#status')).to_contain_text('missing')
            view.goto('about:blank')
            navigate(view, link.split('#')[0]+'#'+'A'*43)
            expect(view.locator('#status')).to_contain_text('Unable to decrypt')
            assert creator.request.get(origin+'/text/api/texts/'+tid).ok
            view.goto('about:blank')
            navigate(view, link)
            try:
                expect(view.locator('#plaintext')).to_be_visible(timeout=15000)
            except AssertionError:
                print('Reader status: '+view.locator('#status').inner_text(),flush=True)
                raise
            assert view.locator('#open').count()==0
            assert view.locator('#plaintext').input_value()==message
            assert view.evaluate('document.documentElement.scrollWidth<=innerWidth')
            assert view.locator('#plaintext').evaluate('(e)=>getComputedStyle(e).overflowY')=='auto'
            if origin.startswith('https:'): time.sleep(2)
            view.reload()
            if mode=='burn':
                expect(view.locator('#status')).to_contain_text('already opened')
                assert creator.request.get(origin+'/text/api/texts/'+tid).status==404
            else:
                expect(view.locator('#plaintext')).to_have_value(message)
            reader.close()
        for url,body,headers in records:
            for key in keys:
                assert key not in url and key.encode() not in body and key not in json.dumps(headers)
            assert SAMPLE.encode() not in body
            assert token not in url and token not in json.dumps(headers)
            assert not headers.get('referer')
            assert url.startswith(origin+'/')
        assert not errors,errors
        if os.environ.get('RUENTEXT_TEST_IDS'):
            Path(os.environ['RUENTEXT_TEST_IDS']).write_text(json.dumps(ids))
        browser.close()
    print('PASS: /text, mobile UI, Turkish/Bulgarian/English UTF-8, long multiline text, AES-GCM round trips, wrong/missing keys, ciphertext-only transfer, fragment secrecy, 24h repeat reads, burn, second-open rejection.')

if __name__=='__main__': run()
