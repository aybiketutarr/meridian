/* Demo shim: no backend here; /api/* calls are answered in the browser with sample data. */
(()=>{
const V=(id,c,e,o)=>({offline:!!o,id,type:"cve",cvss:c,sev:c>=9?"critical":c>=7?"high":c>=4?"medium":"low",kev:false,active:false,exploit:e,epss:null,ai:null,title:"",href:"https://vulners.com/cve/"+id,src:"https://nvd.nist.gov/vuln/detail/"+id,cpe:""});
const DV={"192.168.1.10:21":[V("CVE-2011-2523",9.8,true)],"192.168.1.10:8080":[V("CVE-2021-42013",9.8,true),V("CVE-2021-41773",7.5,true)],"192.168.1.57:80":[V("CVE-2017-17562",8.1,true)]};
const OV={"192.168.1.10:21":[V("CVE-2011-2523",9.8,true,1)],"192.168.1.10:8080":[V("CVE-2021-41773",7.5,true,1)]};
const D=[["192.168.1.1","gateway.lan","Linux 5.15",[[22,"ssh","OpenSSH 9.2"],[80,"http","lighttpd 1.4"],[443,"https",""]],false],
["192.168.1.10","nas.lan","Linux 4.x",[[21,"ftp","vsftpd 2.3.4"],[445,"smb","Samba 4.13"],[5000,"http","Synology DSM"],[8080,"http","Apache httpd 2.4.49"]],true],
["192.168.1.23","printer.lan","",[[631,"ipp","CUPS 2.4"],[9100,"jetdirect",""],[23,"telnet",""]],false],
["192.168.1.42","dev-laptop","Windows 11",[[135,"msrpc",""],[3389,"rdp",""]],false],
["192.168.1.57","cam-garage","Linux 3.x",[[554,"rtsp",""],[80,"http","GoAhead 2.5"]],true],
["192.168.1.88","","",[],false]];
const demo=(lk,off)=>D.map(([i,n,o,ps,v])=>({ip:i,mac:"",name:n,os:o,vuln:v,
 hops:i.endsWith(".1")?[]:["192.168.1.1"].concat(/(42|57)$/.test(i)?["192.168.1.254"]:[]),
 ports:ps.map(([p,s,ver])=>{const hv=/\d/.test(ver),x={port:p,proto:"tcp",service:s,version:ver,ver:hv,cpes:hv?["cpe:/a:demo:"+s]:[],
  scripts:p===445?[{id:"smb-vuln-ms17-010",out:"VULNERABLE: Remote Code Execution (CVE-2017-0143)"}]:[]},d=lk&&DV[i+":"+p]||off&&OV[i+":"+p];
  if(d)x.vulns={mode:lk?"free":"offline",total:d.length,cves:d.length,exploits:d.filter(a=>a.exploit).length,kev:0,items:d};return x})}));
const jobs={},watch=[];let n=0,devices={};
const AI={provider:"anthropic",model:"",port:11434,default_model:"claude-sonnet-5-5",cloud:true,key:true,key_src:"file",providers:["ollama","lmstudio","anthropic","openai"],models:[]};
const res=(c,b)=>new Response(JSON.stringify(b),{status:c,headers:{"Content-Type":"application/json"}});
window.fetch=async(u,o)=>{
 const p=String(u),post=o&&o.method==="POST",b=post?JSON.parse(o.body||"{}"):{};
 if(p==="/api/scan"&&post){
  if(b.ack!==true)return res(400,{error:"Profile/authorization missing",code:"auth"});
  if(!b.demo)return res(400,{error:"This is a browser-only demo: real scans need nmap and the local server. Click “Sample data”.",code:"demo_only"});
  if([...Object.values(jobs)].some(j=>j.status==="running"))return res(409,{error:"A scan is already running. Stop it first.",code:"busy"});
  const id=(++n).toString(16).padStart(8,"0"),j={status:"running",hosts:[],error:"",target:b.target||"demo",profile:b.profile,lookup:!!b.lookup&&b.profile!=="ping",offline:!!b.offline&&b.profile!=="ping",t0:Date.now(),ts:Date.now()/1000,dur:0};
  jobs[id]=j;let k=0;const t=setInterval(()=>{
   if(j.status!=="running"){clearInterval(t);return}
   j.hosts=demo(j.lookup,j.offline).slice(0,++k);
   if(k>=6){j.status="done";j.dur=Math.round((Date.now()-j.t0)/1000);clearInterval(t)}},1200);
  return res(200,{id});}

 /* AI: the demo never calls a model. It shows the same screens with a ready-made answer. */
 if(p==="/api/ai"||p==="/api/ai/config"||p==="/api/ai/preview"||p==="/api/ai/analyze"||/^\/api\/ai\/result\//.test(p)){
  if(p==="/api/ai"&&!post)return res(200,AI);
  if(p==="/api/ai/config"){if("provider"in b){AI.provider=b.provider;AI.cloud=b.provider==="anthropic"||b.provider==="openai";AI.default_model={anthropic:"claude-sonnet-5-5",openai:"gpt-5"}[b.provider]||""}if("model"in b)AI.model=String(b.model).slice(0,100);AI.key=AI.cloud;return res(200,AI)}
  const j=jobs[b.id];if(post&&(!AI.provider))return res(400,{error:"AI is off",code:"ai_off"});if(post&&!j)return res(400,{error:"no data",code:"ai_nodata"});
  const anon=j&&j.hosts.map((h,i)=>({host:"H"+(i+1),os:h.os,ports:h.ports.map(q=>({port:q.port,proto:q.proto,service:q.service,product:q.version.replace(/\s*[\d.]+$/,""),version:(q.version.match(/[\d.]+$/)||[""])[0],cves:(q.vulns?q.vulns.items:[]).map(v=>({id:v.id,cvss:v.cvss,exploit:v.exploit,kev:false}))}))}));
  if(p==="/api/ai/preview")return res(200,{provider:AI.provider,model:AI.model||AI.default_model||"demo",cloud:AI.cloud,payload:{language:b.lang,hosts:anon},consent:"demo"});
  if(p==="/api/ai/analyze"){const tr=b.lang==="tr",ip=n=>(j.hosts[n]||{}).ip||"";
   return res(200,{provider:AI.provider,model:AI.model||AI.default_model||"demo",cloud:AI.cloud,ts:Date.now()/1000,
    summary:tr?"Ağda iki cihaz acil müdahale istiyor: NAS üzerindeki eski vsftpd ve Apache sürümleri ile garajdaki kamera. Yazıcıda Telnet açık. Önce bu üç cihazı kapatıp güncelleyin, sonra geri kalan servisleri gözden geçirin. (Bu bir demo cevabıdır.)":"Two devices need urgent attention: the NAS runs an old vsftpd and Apache, and the garage camera has a known remote flaw. The printer exposes Telnet. Fix these three first, then review the remaining services. (This is a canned demo answer.)",
    priorities:[{host:ip(1),severity:"critical",issue:tr?"vsftpd 2.3.4 (CVE-2011-2523) ve Apache 2.4.49 (CVE-2021-41773) açık ve istismar kodu var.":"vsftpd 2.3.4 (CVE-2011-2523) and Apache 2.4.49 (CVE-2021-41773) are exposed and have public exploits.",fix:tr?"FTP'yi kapatın, Apache'yi 2.4.51 veya üstüne güncelleyin, NAS'ı internetten erişilemez yapın.":"Disable FTP, upgrade Apache to 2.4.51 or later, and make sure the NAS is not reachable from the internet."},
     {host:ip(4),severity:"high",issue:tr?"GoAhead 2.5 kamerası bilinen bir uzaktan kod çalıştırma açığı taşıyor (CVE-2017-17562).":"The GoAhead 2.5 camera has a known remote code execution flaw (CVE-2017-17562).",fix:tr?"Üretici yazılımını güncelleyin; mümkün değilse kamerayı ayrı bir VLAN'a alın.":"Update the firmware; if that is not possible, move the camera to a separate VLAN."},
     {host:ip(2),severity:"medium",issue:tr?"Yazıcıda şifrelenmemiş Telnet (23) açık.":"The printer has unencrypted Telnet (23) open.",fix:tr?"Yazıcı yönetim ayarlarından Telnet'i kapatın.":"Turn Telnet off in the printer's admin settings."}]})}
  return res(404,{error:"not found"})}
 let m;
 if(m=p.match(/^\/api\/scan\/(\w+)$/)){const j=jobs[m[1]];return j?res(200,{status:j.status,hosts:j.hosts,error:j.error,target:j.target,profile:j.profile,lookup:j.lookup,offline:j.offline,elapsed:Math.round((Date.now()-j.t0)/1000)}):res(404,{error:"not found"})}
 if(m=p.match(/^\/api\/stop\/(\w+)$/)){if(jobs[m[1]]){jobs[m[1]].status="stopped"}return res(200,{ok:true})}
 if(p==="/api/history")return res(200,Object.entries(jobs).filter(([,j])=>j.status!=="running").map(([id,j])=>({id,target:j.target,profile:j.profile,hosts:j.hosts.length,ts:j.ts,dur:j.dur})).reverse());
 if(p==="/api/alerts")return res(200,{alerts:[],watch:watch.map(w=>({target:w.target,profile:w.profile,every:w.minutes}))});
 if(p==="/api/net")return res(200,{cidr:"192.168.1.0/24",os:"linux"});
 if(p==="/api/devices"){if(post){const K=/^([0-9A-F]{2}(:[0-9A-F]{2}){5}|ip:\d{1,3}(\.\d{1,3}){3})$/;
   if(b.clear===true)devices={};
   else if(Array.isArray(b.trust)){if(!b.trust.every(k=>K.test(k)))return res(400,{error:"Invalid device",code:"device"});b.trust.forEach(k=>{devices[k]={trusted:true,label:(devices[k]||{}).label||""}})}
   else{if(!K.test(b.key))return res(400,{error:"Invalid device",code:"device"});const e=devices[b.key]=devices[b.key]||{trusted:false,label:""};if("trusted"in b)e.trusted=b.trusted===true;if("label"in b)e.label=String(b.label||"").slice(0,40);if(!e.trusted&&!e.label)delete devices[b.key]}}
  return res(200,{devices})}
 if(p==="/api/watch"&&post){const i=watch.findIndex(w=>w.target===b.target);if(i>=0)watch.splice(i,1);if(+b.minutes)watch.push(b);return res(200,{ok:true})}
 return res(404,{error:"not available in preview"});
};
})();
