import bcrypt from 'bcryptjs';
import { put } from '@vercel/blob';
import { ADMIN_EMAIL, SETUP_TOKEN_HASH, admin, audit, blobToken, databaseUrl, ensureSchema, publish, recentAudit, replaceAll, saveDraft, state } from '../lib/db.js';
import { ADMIN_COOKIE, adminSession, changePassword, checkPassword, requireAdmin, setCookie, setupPassword, sha256, visitorAllowed, visitorSession } from '../lib/auth.js';

const json=(res,status,body)=>{res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify(body));};
const sameOrigin=req=>{const origin=req.headers.origin;if(!origin)return true;try{return new URL(origin).host===(req.headers['x-forwarded-host']||req.headers.host);}catch{return false;}};
const ip=req=>String(req.headers['x-forwarded-for']||req.socket?.remoteAddress||'unknown').split(',')[0].trim();
async function body(req){if(req.body!==undefined&&req.body!==null){if(typeof req.body==='string')return req.body?JSON.parse(req.body):{};if(Buffer.isBuffer(req.body))return JSON.parse(req.body.toString()||'{}');return req.body;}let s='';for await(const c of req){s+=c;if(s.length>18*1024*1024)throw new Error('Request is too large.');}return s?JSON.parse(s):{};}
function pathOf(req){const p=req.query?.path;if(Array.isArray(p))return p.join('/');if(typeof p==='string')return p;return String(req.url||'').replace(/^\/api\/?/,'').split('?')[0];}
function fail(res,e,status=400){console.error(e);json(res,status,{error:e?.message||'Request failed.'});}

async function publicContent(req,res){
  const s=await state(), project=structuredClone(s.published), access=project.settings?.access||{}, mode=access.mode||'public';
  if(mode==='maintenance')return json(res,200,{gate:'maintenance',message:access.maintenanceMessage||'The site is being updated.'});
  if(mode==='passcode'&&!(await visitorAllowed(req)))return json(res,200,{gate:'passcode',message:access.message||'This preview is protected.',hint:access.hint||'Enter the access code.'});
  if(project.settings?.access){delete project.settings.access.visitorPasscodeHash;delete project.settings.access.visitorPasscodePlain;}
  json(res,200,{project,updatedAt:s.lastPublishedAt,cloud:true});
}
async function publicAccess(req,res){const b=await body(req),s=await state(),a=s.published.settings?.access||{};if(a.mode!=='passcode')return json(res,200,{ok:true});const code=String(b.passcode||'');const ok=a.visitorPasscodeHash?await bcrypt.compare(code,a.visitorPasscodeHash):false;if(!ok)return json(res,401,{error:'Incorrect access code.'});await visitorSession(res,a.rememberHours||24);json(res,200,{ok:true});}
async function authStatus(req,res){const a=await admin(),session=await requireAdmin(req);json(res,200,{email:ADMIN_EMAIL,setupRequired:!a?.setup_completed,loggedIn:Boolean(session),cloud:true});}
async function authSetup(req,res){const b=await body(req),email=String(b.email||'').toLowerCase(),password=String(b.password||''),token=String(b.token||'');if(email!==ADMIN_EMAIL)return json(res,403,{error:'This email is not authorized.'});if(password.length<10)return json(res,400,{error:'Use at least 10 characters.'});const a=await admin();if(a?.setup_completed)return json(res,409,{error:'Setup is already complete.'});if(!token||sha256(token)!==SETUP_TOKEN_HASH)return json(res,403,{error:'The one-time setup link is invalid.'});const updated=await setupPassword(password);await adminSession(res,updated.session_version);json(res,200,{ok:true,email:ADMIN_EMAIL});}
async function authLogin(req,res){const b=await body(req),email=String(b.email||'').toLowerCase(),password=String(b.password||'');if(email!==ADMIN_EMAIL)return json(res,403,{error:'This email is not authorized.'});const result=await checkPassword(password);if(!result.ok)return json(res,result.locked?429:401,{error:result.locked?'Too many attempts. Try again in 15 minutes.':'Incorrect email or password.'});await adminSession(res,result.admin.session_version);await audit(ADMIN_EMAIL,'admin_login',{ip:ip(req)});json(res,200,{ok:true});}
async function authLogout(req,res){setCookie(res,ADMIN_COOKIE,'',{maxAge:-1});json(res,200,{ok:true});}
async function authPassword(req,res){const b=await body(req),current=String(b.current||''),next=String(b.next||'');if(next.length<10)return json(res,400,{error:'Use at least 10 characters.'});if(!(await changePassword(current,next)))return json(res,401,{error:'Current password is incorrect.'});setCookie(res,ADMIN_COOKIE,'',{maxAge:-1});json(res,200,{ok:true});}
async function adminContent(req,res){const a=await requireAdmin(req);if(!a)return json(res,401,{error:'Sign in required.'});if(req.method==='GET')return json(res,200,{...(await state()),audit:await recentAudit(30)});const b=await body(req);let draft=b.draft,history=b.history;if(draft?.settings?.access?.visitorPasscodePlain){const code=String(draft.settings.access.visitorPasscodePlain);if(code.length<4)return json(res,400,{error:'Visitor passcode must be at least four characters.'});draft.settings.access.visitorPasscodeHash=await bcrypt.hash(code,12);delete draft.settings.access.visitorPasscodePlain;}json(res,200,await saveDraft(draft,history,ADMIN_EMAIL));}
async function adminPublish(req,res){const a=await requireAdmin(req);if(!a)return json(res,401,{error:'Sign in required.'});json(res,200,await publish(ADMIN_EMAIL));}
async function adminImport(req,res){const a=await requireAdmin(req);if(!a)return json(res,401,{error:'Sign in required.'});const b=await body(req);json(res,200,await replaceAll(b.project,ADMIN_EMAIL));}
async function adminUpload(req,res){const a=await requireAdmin(req);if(!a)return json(res,401,{error:'Sign in required.'});const b=await body(req),data=String(b.dataUrl||''),match=data.match(/^data:(image\/[a-z0-9.+-]+);base64,(.+)$/i);if(!match)return json(res,400,{error:'Upload a valid image.'});const bytes=Buffer.from(match[2],'base64');if(bytes.length>8*1024*1024)return json(res,413,{error:'Image must be under 8 MB.'});const ext=(match[1].split('/')[1]||'jpg').replace('jpeg','jpg');const safe=String(b.name||'portrait').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,60)||'portrait';const token=blobToken();if(!token)return json(res,503,{error:'Vercel Blob is not connected.'});const result=await put(`portraits/${safe}.${ext}`,bytes,{access:'public',addRandomSuffix:true,contentType:match[1],token});await audit(ADMIN_EMAIL,'portrait_uploaded',{url:result.url});json(res,200,{url:result.url});}
async function health(req,res){try{await ensureSchema();const s=await state();json(res,200,{ok:true,database:Boolean(databaseUrl()),blob:Boolean(blobToken()),people:s.published.people.length,categories:s.published.categories.length,cloud:true});}catch(e){fail(res,e,500);}}

export default async function handler(req,res){
  try{
    const path=pathOf(req);
    if(req.method==='OPTIONS'){res.statusCode=204;return res.end();}
    if(!sameOrigin(req)&&req.method!=='GET')return json(res,403,{error:'Invalid request origin.'});
    if(path==='health'&&req.method==='GET')return health(req,res);
    if(path==='public/content'&&req.method==='GET')return publicContent(req,res);
    if(path==='public/access'&&req.method==='POST')return publicAccess(req,res);
    if(path==='auth/status'&&req.method==='GET')return authStatus(req,res);
    if(path==='auth/setup'&&req.method==='POST')return authSetup(req,res);
    if(path==='auth/login'&&req.method==='POST')return authLogin(req,res);
    if(path==='auth/logout'&&req.method==='POST')return authLogout(req,res);
    if(path==='auth/password'&&req.method==='POST'){if(!(await requireAdmin(req)))return json(res,401,{error:'Sign in required.'});return authPassword(req,res);}
    if(path==='admin/content'&&(req.method==='GET'||req.method==='PUT'))return adminContent(req,res);
    if(path==='admin/publish'&&req.method==='POST')return adminPublish(req,res);
    if(path==='admin/import'&&req.method==='POST')return adminImport(req,res);
    if(path==='admin/upload'&&req.method==='POST')return adminUpload(req,res);
    if(path==='admin/generate-image'&&req.method==='POST')return json(res,503,{error:'AI portrait generation needs an image provider credential. Uploads and image URLs are available now.'});
    json(res,404,{error:'Not found.'});
  }catch(e){fail(res,e,500);}
}
