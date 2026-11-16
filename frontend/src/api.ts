let csrf='';
export async function api<T=any>(path:string,init:RequestInit={}):Promise<T>{
  const headers=new Headers(init.headers); if(init.body && !(init.body instanceof FormData)) headers.set('Content-Type','application/json'); if(csrf && init.method && init.method!=='GET') headers.set('X-CSRF-Token',csrf);
  const res=await fetch('/api'+path,{...init,headers,credentials:'include'}); const data=await res.json().catch(()=>({detail:res.statusText})); if(!res.ok) throw new Error(data.detail||'Request failed'); return data as T;
}
export const setCsrf=(value:string)=>{csrf=value};
