/* Demo shim: no backend here; /api/* calls are answered in the browser with sample data. */
(()=>{
const V=(id,c,e)=>({id,type:"cve",cvss:c,sev:c>=9?"critical":c>=7?"high":c>=4?"medium":"low",kev:false,active:false,exploit:e,epss:null,ai:null,title:"",href:"https://vulners.com/cve/"+id,src:"https://nvd.nist.gov/vuln/detail/"+id,cpe:""});
const DV={"192.168.1.10:21":[V("CVE-2011-2523",9.8,true)],"192.168.1.10:8080":[V("CVE-2021-42013",9.8,true),V("CVE-2021-41773",7.5,true)],"192.168.1.57:80":[V("CVE-2017-17562",8.1,true)]};
const D=[["192.168.1.1","gateway.lan","Linux 5.15",[[22,"ssh","OpenSSH 9.2"],[80,"http","lighttpd 1.4"],[443,"https",""]],false],
["192.168.1.10","nas.lan","Linux 4.x",[[21,"ftp","vsftpd 2.3.4"],[445,"smb","Samba 4.13"],[5000,"http","Synology DSM"],[8080,"http","Apache httpd 2.4.49"]],true],
["192.168.1.23","printer.lan","",[[631,"ipp","CUPS 2.4"],[9100,"jetdirect",""],[23,"telnet",""]],false],
["192.168.1.42","dev-laptop","Windows 11",[[135,"msrpc",""],[3389,"rdp",""]],false],
["192.168.1.57","cam-garage","Linux 3.x",[[554,"rtsp",""],[80,"http","GoAhead 2.5"]],true],
["192.168.1.88","","",[],false]];
const demo=lk=>D.map(([i,n,o,ps,v])=>({ip:i,mac:"",name:n,os:o,vuln:v,
 hops:i.endsWith(".1")?[]:["192.168.1.1"].concat(/(42|57)$/.test(i)?["192.168.1.254"]:[]),
 ports:ps.map(([p,s,ver])=>{const hv=/\d/.test(ver),x={port:p,proto:"tcp",service:s,version:ver,ver:hv,cpes:hv?["cpe:/a:demo:"+s]:[],
  scripts:p===445?[{id:"smb-vuln-ms17-010",out:"VULNERABLE: Remote Code Execution (CVE-2017-0143)"}]:[]},d=lk&&DV[i+":"+p];
  if(d)x.vulns={mode:"free",total:d.length,cves:d.length,exploits:d.filter(a=>a.exploit).length,kev:0,items:d};return x})}));
const jobs={},watch=[];let n=0;
const res=(c,b)=>new Response(JSON.stringify(b),{status:c,headers:{"Content-Type":"application/json"}});
window.fetch=async(u,o)=>{
 const p=String(u),post=o&&o.method==="POST",b=post?JSON.parse(o.body||"{}"):{};
 if(p==="/api/scan"&&post){
  if(b.ack!==true)return res(400,{error:"Profile/authorization missing"});
  if(!b.demo)return res(400,{error:"This is a browser-only demo: real scans need nmap and the local server. Click “Sample data”."});
  if([...Object.values(jobs)].some(j=>j.status==="running"))return res(409,{error:"A scan is already running. Stop it first."});
  const id=(++n).toString(16).padStart(8,"0"),j={status:"running",hosts:[],error:"",target:b.target||"demo",profile:b.profile,lookup:!!b.lookup&&b.profile!=="ping",t0:Date.now(),ts:Date.now()/1000,dur:0};
  jobs[id]=j;let k=0;const t=setInterval(()=>{
   if(j.status!=="running"){clearInterval(t);return}
   j.hosts=demo(j.lookup).slice(0,++k);
   if(k>=6){j.status="done";j.dur=Math.round((Date.now()-j.t0)/1000);clearInterval(t)}},1200);
  return res(200,{id});}
 let m;
 if(m=p.match(/^\/api\/scan\/(\w+)$/)){const j=jobs[m[1]];return j?res(200,{status:j.status,hosts:j.hosts,error:j.error,target:j.target,profile:j.profile,lookup:j.lookup,elapsed:Math.round((Date.now()-j.t0)/1000)}):res(404,{error:"not found"})}
 if(m=p.match(/^\/api\/stop\/(\w+)$/)){if(jobs[m[1]]){jobs[m[1]].status="stopped"}return res(200,{ok:true})}
 if(p==="/api/history")return res(200,Object.entries(jobs).filter(([,j])=>j.status!=="running").map(([id,j])=>({id,target:j.target,profile:j.profile,hosts:j.hosts.length,ts:j.ts,dur:j.dur})).reverse());
 if(p==="/api/alerts")return res(200,{alerts:[],watch:watch.map(w=>({target:w.target,profile:w.profile,every:w.minutes}))});
 if(p==="/api/net")return res(200,{cidr:"192.168.1.0/24"});
 if(p==="/api/watch"&&post){const i=watch.findIndex(w=>w.target===b.target);if(i>=0)watch.splice(i,1);if(+b.minutes)watch.push(b);return res(200,{ok:true})}
 return res(404,{error:"not available in preview"});
};
})();
