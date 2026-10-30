// سيرفر الكافيه — Node.js بدون أي مكتبات خارجية (يحتاج Node 18 أو أحدث)
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,FILE=process.env.DATA_FILE||path.join(__dirname,'data.json'),TZ=process.env.TZ_NAME||'Africa/Cairo';
let D={users:[],att:[],ent:[],menu:[],ord:[],days:[],secret:crypto.randomBytes(32).toString('hex')};
try{D={...D,...JSON.parse(fs.readFileSync(FILE,'utf8'))}}catch(e){}
let tm=null;const persist=()=>{clearTimeout(tm);tm=setTimeout(()=>{try{fs.writeFileSync(FILE+'.tmp',JSON.stringify(D));fs.renameSync(FILE+'.tmp',FILE)}catch(e){console.error(e)}},300)};persist();
const INDEX=fs.readFileSync(path.join(__dirname,'public','index.html'));
const day=()=>new Date().toLocaleDateString('en-CA',{timeZone:TZ}),rid=()=>crypto.randomUUID().replace(/-/g,'').slice(0,12);
const hash=(p,s=crypto.randomBytes(16).toString('hex'))=>s+':'+crypto.scryptSync(p,s,32).toString('hex');
const check=(p,h)=>{const[s,x]=h.split(':'),y=crypto.scryptSync(p,s,32).toString('hex');return crypto.timingSafeEqual(Buffer.from(x),Buffer.from(y))};
const mac=b=>crypto.createHmac('sha256',D.secret).update(b).digest('base64url');
const sign=u=>{const b=Buffer.from(JSON.stringify({id:u.id,exp:Date.now()+30*864e5})).toString('base64url');return b+'.'+mac(b)};
const verify=t=>{try{const[b,m]=t.split('.'),e=mac(b);if(m.length!==e.length||!crypto.timingSafeEqual(Buffer.from(m),Buffer.from(e)))return null;const p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()&&D.users.find(u=>u.id===p.id)||null}catch(e){return null}};
const pub=u=>({id:u.id,name:u.name,user:u.user,role:u.role,salary:u.salary});
const stateFor=u=>u.role==='admin'?{users:D.users.map(pub),att:D.att,ent:D.ent,menu:D.menu,ord:D.ord,days:D.days}:{users:D.users.map(x=>({id:x.id,name:x.name,role:x.role})),att:D.att.filter(a=>a.uid===u.id),ent:[],menu:D.menu,ord:D.ord,days:[]};
const clients=new Set();
function broadcast(){for(const c of clients){const u=D.users.find(x=>x.id===c.uid);if(!u){c.res.end();clients.delete(c);continue}c.res.write('data: '+JSON.stringify(stateFor(u))+'\n\n')}}
const hits=new Map(),recent=(k,ms)=>(hits.get(k)||[]).filter(t=>Date.now()-t<ms),hit=k=>hits.set(k,[...recent(k,6e5),Date.now()]);
async function mail(subject,text){const k=process.env.RESEND_API_KEY,to=process.env.MAIL_TO;if(!k||!to)return;try{await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+k,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.MAIL_FROM||'Cafe <onboarding@resend.dev>',to:to.split(','),subject,text})})}catch(e){console.error('mail',e.message)}}
const readBody=req=>new Promise((ok,no)=>{let n=0,b=[];req.on('data',c=>{n+=c.length;if(n>1e5){no({c:413,msg:'كبير'});req.destroy()}else b.push(c)});req.on('end',()=>{try{ok(b.length?JSON.parse(Buffer.concat(b)):{})}catch(e){no({c:400,msg:'بيانات غلط'})}})});
const fail=(c,msg)=>{throw{c,msg}},str=(v,n)=>String(v==null?'':v).trim().slice(0,n);
const NX={new:'prep',prep:'ready',ready:'served',served:'paid'};
http.createServer(async(req,res)=>{
 const u=new URL(req.url,'http://x'),p=u.pathname,m=req.method,ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress;
 const out=(c,o)=>{res.writeHead(c,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(o))};
 if(m==='GET'&&(p==='/'||p==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(INDEX)}
 try{
  if(!p.startsWith('/api/'))fail(404,'مش موجود');
  const r=p.slice(5).split('/'),b=(m==='POST'||m==='PUT')?await readBody(req):{};
  const tk=(req.headers.authorization||'').replace('Bearer ','')||u.searchParams.get('t')||'',me=tk?verify(tk):null;
  const auth=()=>me||fail(401,'سجل دخول الأول'),admin=()=>auth().role==='admin'||fail(403,'للأدمن بس');
  const done=()=>{persist();broadcast();out(200,{ok:true})};
  const k=r[0];
  if(m==='GET'&&k==='info')return out(200,{hasUsers:D.users.length>0});
  if(m==='GET'&&k==='menu')return out(200,{menu:D.menu});
  if(m==='POST'&&k==='setup'){if(D.users.length)fail(403,'متعمل قبل كده');const n=str(b.name,40),us=str(b.user,30).toLowerCase(),pw=str(b.pass,100);if(!n||!us||pw.length<4)fail(400,'اكمل البيانات');const a={id:rid(),name:n,user:us,hash:hash(pw),role:'admin',salary:0};D.users.push(a);persist();return out(200,{token:sign(a)})}
  if(m==='POST'&&k==='login'){if(recent('l'+ip,6e5).length>=10)fail(429,'محاولات كتير، استنى شوية');const us=D.users.find(x=>x.user===str(b.user,30).toLowerCase());if(!us||!check(String(b.pass||''),us.hash)){hit('l'+ip);fail(401,'اليوزر أو كلمة السر غلط')}return out(200,{token:sign(us)})}
  if(m==='GET'&&k==='state')return out(200,{me:pub(auth()),state:stateFor(me)});
  if(m==='GET'&&k==='backup'){admin();res.writeHead(200,{'Content-Type':'application/json','Content-Disposition':'attachment; filename=cafe-backup.json'});return res.end(JSON.stringify({...D,secret:undefined}))}
  if(m==='GET'&&k==='events'){auth();res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});const c={res,uid:me.id};clients.add(c);res.write('data: '+JSON.stringify(stateFor(me))+'\n\n');const hb=setInterval(()=>res.write(': hb\n\n'),25000);req.on('close',()=>{clearInterval(hb);clients.delete(c)});return}
  if(m==='POST'&&k==='order'&&!r[1]){
   if(!me&&recent('o'+ip,6e5).length>=20)fail(429,'طلبات كتير، استنى شوية');
   const table=str(b.table,20);if(!table)fail(400,'اكتب رقم الترابيزة');if(!Array.isArray(b.items)||!b.items.length||b.items.length>40)fail(400,'اختار أصناف');
   const items=b.items.map(i=>{const x=D.menu.find(y=>y.id===i.id),q=Math.floor(+i.q);return x&&q>=1&&q<=50?{n:x.n,p:x.p,q}:null}).filter(Boolean);if(!items.length)fail(400,'أصناف غير صحيحة');
   const o={id:crypto.randomUUID(),table,items,note:str(b.note,200),status:'new',t:Date.now(),uid:me?me.id:'guest'};D.ord.push(o);if(!me)hit('o'+ip);
   mail('🔔 ترابيزة '+table+' طلبت أوردر',items.map(i=>i.q+' × '+i.n).join('\n')+(o.note?'\nملاحظة: '+o.note:''));persist();broadcast();return out(200,{id:o.id})}
  if(m==='GET'&&k==='order'&&r[1]){const o=D.ord.find(x=>x.id===r[1]);if(!o)fail(404,'مش موجود');return out(200,{table:o.table,status:o.status})}
  if(m==='POST'&&k==='order'&&r[2]==='advance'){auth();const o=D.ord.find(x=>x.id===r[1]);if(!o)fail(404,'مش موجود');const nx=NX[o.status];if(!nx)fail(400,'اتقفل');o.status=nx;
   if(nx==='paid'){o.pt=Date.now();o.date=day();const t=o.items.reduce((a,i)=>a+i.p*i.q,0);let d=D.days.find(x=>x.date===o.date);if(!d)D.days.push(d={id:o.date,date:o.date,amt:0,cnt:0});d.amt+=t;d.cnt++;D.ord=D.ord.filter(x=>x.status!=='paid'||Date.now()-x.pt<30*864e5)}return done()}
  if(m==='POST'&&k==='punch'){auth();const o=D.att.find(a=>a.uid===me.id&&!a.out);if(o)o.out=Date.now();else D.att.push({id:rid(),uid:me.id,date:day(),in:Date.now(),out:0});return done()}
  if(m==='POST'&&k==='expense'){admin();const a=+b.amt;if(!(a>0))fail(400,'المبلغ غلط');D.ent.push({id:rid(),date:day(),amt:a,note:str(b.note,100),uid:me.id});return done()}
  if(m==='POST'&&k==='menu'){admin();const n=str(b.n,60),pr=+b.p;if(!n||!(pr>0))fail(400,'اكتب الاسم والسعر');D.menu.push({id:rid(),n,p:pr,c:str(b.c,30)||'عام',e:str(b.e,8)||'☕'});return done()}
  if(m==='DELETE'&&k==='menu'){admin();D.menu=D.menu.filter(x=>x.id!==r[1]);return done()}
  if(m==='POST'&&k==='users'&&!r[1]){admin();const n=str(b.name,40),us=str(b.user,30).toLowerCase(),pw=str(b.pass,100);if(!n||!us||pw.length<4)fail(400,'اكمل البيانات');if(D.users.some(x=>x.user===us))fail(400,'اليوزر ده موجود');D.users.push({id:rid(),name:n,user:us,hash:hash(pw),role:'emp',salary:+b.salary||0});return done()}
  if(m==='POST'&&k==='users'&&r[2]==='pw'){admin();const x=D.users.find(y=>y.id===r[1]),pw=str(b.pass,100);if(!x||pw.length<4)fail(400,'الباسورد قصير');x.hash=hash(pw);return done()}
  if(m==='DELETE'&&k==='users'){admin();const x=D.users.find(y=>y.id===r[1]);if(!x||x.role==='admin')fail(400,'مينفعش');D.users=D.users.filter(y=>y.id!==x.id);D.att=D.att.filter(a=>a.uid!==x.id);return done()}
  if(m==='DELETE'&&k==='rec'&&['ord','att','ent'].includes(r[1])){admin();D[r[1]]=D[r[1]].filter(x=>x.id!==r[2]);return done()}
  fail(404,'مش موجود')
 }catch(e){if(e&&e.c)return out(e.c,{error:e.msg});console.error(e);out(500,{error:'خطأ في السيرفر'})}
}).listen(PORT,()=>console.log('Cafe server on :'+PORT));
