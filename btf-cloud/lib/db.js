import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';
import { createSeed } from './seed.js';

export const ADMIN_EMAIL='jeff@labs.vip';
export const SETUP_TOKEN_HASH='8b2f283a715ed7ff469d5150d98645f52b532d380da4e33f835d95a75251574d';
export const RECOVERY_TOKEN_HASH='d0f98bee4b2a96c8081c1b476b29dc226da7341612598cfa45628577a8fba959';
let dbClient=null, schemaPromise=null;

function envValue(...names){
  for(const name of names) if(process.env[name]) return process.env[name];
  for(const [name,value] of Object.entries(process.env)) if(value && names.some(n=>name.endsWith(n))) return value;
  return '';
}
export function databaseUrl(){return envValue('DATABASE_URL','POSTGRES_URL','NEON_DATABASE_URL');}
export function blobToken(){return envValue('BLOB_READ_WRITE_TOKEN');}
export function db(){
  if(!dbClient){const url=databaseUrl(); if(!url) throw new Error('Database connection is not configured.'); dbClient=neon(url);}
  return dbClient;
}
export async function ensureSchema(){
  if(!schemaPromise) schemaPromise=migrate().catch(e=>{schemaPromise=null;throw e;});
  return schemaPromise;
}
async function migrate(){
  const sql=db();
  await sql`CREATE TABLE IF NOT EXISTS btf_content (id integer PRIMARY KEY CHECK(id=1), draft jsonb NOT NULL, published jsonb NOT NULL, history jsonb NOT NULL DEFAULT '[]'::jsonb, updated_at timestamptz NOT NULL DEFAULT now(), last_published_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS btf_admins (email text PRIMARY KEY, password_hash text, setup_token_hash text, recovery_token_hash text, setup_completed boolean NOT NULL DEFAULT false, session_version integer NOT NULL DEFAULT 1, failed_attempts integer NOT NULL DEFAULT 0, locked_until timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS btf_meta (key text PRIMARY KEY, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS btf_audit (id bigserial PRIMARY KEY, actor_email text, action text NOT NULL, detail jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS btf_rate_limits (key text PRIMARY KEY, attempts integer NOT NULL DEFAULT 0, locked_until timestamptz, updated_at timestamptz NOT NULL DEFAULT now())`;
  const seed=createSeed();
  await sql`INSERT INTO btf_content(id,draft,published,history) VALUES(1,${JSON.stringify(seed)}::jsonb,${JSON.stringify(seed)}::jsonb,'[]'::jsonb) ON CONFLICT(id) DO NOTHING`;
  await sql`INSERT INTO btf_admins(email,setup_token_hash,recovery_token_hash) VALUES(${ADMIN_EMAIL},${SETUP_TOKEN_HASH},${RECOVERY_TOKEN_HASH}) ON CONFLICT(email) DO NOTHING`;
  await sql`INSERT INTO btf_meta(key,value) VALUES('session_secret',${JSON.stringify(crypto.randomBytes(48).toString('base64url'))}::jsonb) ON CONFLICT(key) DO NOTHING`;
  await sql`INSERT INTO btf_meta(key,value) VALUES('schema_version','2'::jsonb) ON CONFLICT(key) DO NOTHING`;
}
export async function state(){
  await ensureSchema(); const rows=await db()`SELECT draft,published,history,updated_at,last_published_at FROM btf_content WHERE id=1`; const r=rows[0];
  return {draft:r.draft,published:r.published,history:Array.isArray(r.history)?r.history:[],updatedAt:new Date(r.updated_at).toISOString(),lastPublishedAt:new Date(r.last_published_at).toISOString(),mode:'cloud'};
}
export async function saveDraft(draft,history,actor){
  await ensureSchema(); validate(draft); const safeHistory=Array.isArray(history)?history.slice(0,20):[];
  await db()`UPDATE btf_content SET draft=${JSON.stringify(draft)}::jsonb,history=${JSON.stringify(safeHistory)}::jsonb,updated_at=now() WHERE id=1`;
  await audit(actor,'draft_saved',{people:draft.people.length,categories:draft.categories.length}); return state();
}
export async function publish(actor){await ensureSchema();await db()`UPDATE btf_content SET published=draft,last_published_at=now(),updated_at=now() WHERE id=1`;await audit(actor,'content_published',{});return state();}
export async function replaceAll(project,actor){validate(project);const history=[];await db()`UPDATE btf_content SET draft=${JSON.stringify(project)}::jsonb,published=${JSON.stringify(project)}::jsonb,history=${JSON.stringify(history)}::jsonb,last_published_at=now(),updated_at=now() WHERE id=1`;await audit(actor,'project_replaced',{people:project.people.length});return state();}
function validate(x){if(!x||typeof x!=='object'||!Array.isArray(x.people)||x.people.length>5000)throw new Error('Invalid people collection.');if(!Array.isArray(x.categories)||x.categories.length>250)throw new Error('Invalid categories collection.');if(Buffer.byteLength(JSON.stringify(x))>14*1024*1024)throw new Error('Project is too large.');}
export async function admin(){await ensureSchema();const rows=await db()`SELECT * FROM btf_admins WHERE email=${ADMIN_EMAIL}`;return rows[0]||null;}
export async function secret(){await ensureSchema();const rows=await db()`SELECT value FROM btf_meta WHERE key='session_secret'`;return rows[0]?.value;}
export async function audit(actor,action,detail={}){await db()`INSERT INTO btf_audit(actor_email,action,detail) VALUES(${actor||null},${action},${JSON.stringify(detail)}::jsonb)`;}
export async function recentAudit(limit=30){await ensureSchema();return db()`SELECT id,actor_email,action,detail,created_at FROM btf_audit ORDER BY id DESC LIMIT ${Math.min(100,Math.max(1,limit))}`;}
export async function rateLimit(key,ok=false){
  await ensureSchema(); const rows=await db()`SELECT attempts,locked_until FROM btf_rate_limits WHERE key=${key}`; const r=rows[0];
  if(r?.locked_until && new Date(r.locked_until)>new Date()) return {blocked:true,retryAt:r.locked_until};
  if(ok){await db()`DELETE FROM btf_rate_limits WHERE key=${key}`;return {blocked:false};}
  const attempts=Number(r?.attempts||0)+1, lock=attempts>=8;
  await db()`INSERT INTO btf_rate_limits(key,attempts,locked_until,updated_at) VALUES(${key},${lock?0:attempts},${lock?new Date(Date.now()+15*60000).toISOString():null},now()) ON CONFLICT(key) DO UPDATE SET attempts=EXCLUDED.attempts,locked_until=EXCLUDED.locked_until,updated_at=now()`;
  return {blocked:lock};
}
