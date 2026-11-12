const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{...JSON_HEADERS,...headers}});
const COOKIE = "qm_admin";
const enc = new TextEncoder();
function b64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")}
function unb64(s){s=s.replace(/-/g,"+").replace(/_/g,"/");return Uint8Array.from(atob(s+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))}
async function sign(value, secret){const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);return b64(await crypto.subtle.sign("HMAC",key,enc.encode(value)))}
async function makeToken(secret){const payload=b64(enc.encode(JSON.stringify({exp:Date.now()+8*60*60*1000,nonce:crypto.randomUUID()})));return payload+"."+await sign(payload,secret)}
async function valid(request,env){const raw=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1);if(!raw)return false;const [payload,sig]=raw.split(".");if(!payload||!sig)return false;try{const expected=await sign(payload,env.SESSION_SECRET);if(expected!==sig)return false;const data=JSON.parse(new TextDecoder().decode(unb64(payload)));return data.exp>Date.now()}catch{return false}}
function cookie(value,maxAge){return `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`}
async function body(request){try{return await request.json()}catch{return null}}
function validDrive(s){try{const u=new URL(s);return u.protocol==="https:"&&["drive.google.com","docs.google.com"].includes(u.hostname)}catch{return false}}
function clean(v){return {title:String(v.title||"").trim(),slug:String(v.slug||"").trim().toLowerCase(),type:v.type==="Series"?"Series":"Movie",year:String(v.year||"").trim(),description:String(v.description||"").trim(),poster:String(v.poster||"").trim(),drive:String(v.drive||"").trim()}}
function validate(v){if(!v.title||v.title.length>100) return "Title is required (maximum 100 characters).";if(!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(v.slug))return "Slug must use lowercase letters, numbers and hyphens.";if(!validDrive(v.drive))return "Enter a valid HTTPS Google Drive URL.";if(v.poster){try{const u=new URL(v.poster);if(u.protocol!=="https:")return "Poster URL must use HTTPS."}catch{return "Poster URL is invalid."}}if(v.description.length>500)return "Description is too long.";return null}
export default {
 async fetch(request,env){
  const url=new URL(request.url),path=url.pathname,method=request.method;
  if(!env.DB||!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return json({error:"Server setup incomplete. Configure D1 and the ADMIN_PASSWORD and SESSION_SECRET secrets."},503);
  if(path==="/api/login"&&method==="POST"){const b=await body(request);if(!b||typeof b.password!=="string"||b.password!==env.ADMIN_PASSWORD)return json({error:"Incorrect password."},401);const token=await makeToken(env.SESSION_SECRET);return json({ok:true},{status:200,headers:{"set-cookie":cookie(token,28800)}})}
  if(path==="/api/logout"&&method==="POST")return json({ok:true},{status:200,headers:{"set-cookie":cookie("",0)}});
  if(path==="/api/me"&&method==="GET")return await valid(request,env)?json({ok:true}):json({error:"Not logged in."},401);
  if(path==="/api/videos"&&method==="GET"){const {results}=await env.DB.prepare("SELECT id,title,slug,type,year,description,poster,drive FROM videos ORDER BY created_at DESC").all();return json(results)}
  if(!path.startsWith("/api/videos"))return new Response("Not found",{status:404});
  if(!await valid(request,env))return json({error:"Admin login required."},401);
  if(path==="/api/videos"&&method==="POST"){
   const b=await body(request);if(!b)return json({error:"Invalid JSON."},400);const v=clean(b),err=validate(v);if(err)return json({error:err},400);
   const id=crypto.randomUUID();try{await env.DB.prepare("INSERT INTO videos (id,title,slug,type,year,description,poster,drive) VALUES (?,?,?,?,?,?,?,?)").bind(id,v.title,v.slug,v.type,v.year,v.description,v.poster,v.drive).run();return json({id,...v},201)}catch{return json({error:"Could not save. The slug may already exist."},409)}
  }
  const match=path.match(/^\/api\/videos\/([a-f0-9-]+)$/i);if(!match)return json({error:"Not found."},404);const id=match[1];
  if(method==="PUT"){const b=await body(request);if(!b)return json({error:"Invalid JSON."},400);const v=clean(b),err=validate(v);if(err)return json({error:err},400);try{const r=await env.DB.prepare("UPDATE videos SET title=?,slug=?,type=?,year=?,description=?,poster=?,drive=? WHERE id=?").bind(v.title,v.slug,v.type,v.year,v.description,v.poster,v.drive,id).run();return r.meta.changes?json({id,...v}):json({error:"Entry not found."},404)}catch{return json({error:"Could not update. The slug may already exist."},409)}}
  if(method==="DELETE"){const r=await env.DB.prepare("DELETE FROM videos WHERE id=?").bind(id).run();return r.meta.changes?json({ok:true}):json({error:"Entry not found."},404)}
  return json({error:"Method not allowed."},405);
 }
};