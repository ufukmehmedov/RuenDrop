async function authorize() {
  const token=location.hash.slice(1);
  if(!token) return;
  history.replaceState(null,'',location.pathname);
  try {
    const response=await fetch('/drop/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token}),credentials:'same-origin'});
    if(!response.ok) throw Error();
    location.replace('/drop/');
  } catch { document.querySelector('#status').textContent='Invite link is invalid or unavailable.'; }
}
window.addEventListener('hashchange',authorize);
authorize();
