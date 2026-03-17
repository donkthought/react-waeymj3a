import { useState, useEffect, useRef, useCallback, memo } from "react";

const GFONT = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap";
const M = "'Share Tech Mono','Courier New',monospace";
const P = {
  bg:"#080b10",panel:"#0b1219",alt:"#0f1a26",border:"#1a3352",
  teal:"#00ffe0",tealD:"#006655",
  amber:"#ffb700",amberD:"#7a4f00",
  blue:"#3db8ff",blueD:"#0a3a5c",
  green:"#00ff88",greenD:"#004433",
  red:"#ff2255",redD:"#4a0015",
  purple:"#cc44ff",purpleD:"#2d0055",
  pink:"#ff44cc",pinkD:"#4a0033",
  orange:"#ff7700",
  text:"#b8d8f0",dim:"#2e5070",
  audio:"#ff88ee",
};
function scoreColor(s){return s>65?P.green:s>40?P.amber:P.red;}
const POOL="!@#$%^&*01X+=-:;.,?abcdefghijklmnopqrstuvwxyz0123456789";
function hexRgb(h){const x=h.replace("#","");return[parseInt(x.slice(0,2),16)||0,parseInt(x.slice(2,4),16)||0,parseInt(x.slice(4,6),16)||0];}

// ── SECURITY ──────────────────────────────────────────────────────────────────
function isValidUrl(raw){try{const u=new URL(raw.trim());return u.protocol==="http:"||u.protocol==="https:";}catch(e){return false;}}
function safeHref(raw){try{const u=new URL(raw);if(u.protocol!=="http:"&&u.protocol!=="https:")return"#";return raw;}catch(e){return"#";}}
function classifyError(e){const m=e.message||"";if(m.indexOf("HTTP 4")!==-1)return"API key or quota issue.";if(m.indexOf("HTTP 5")!==-1)return"Server error. Try again.";if(m.indexOf("No JSON")!==-1)return"Analysis returned no data. Try again.";if(m.indexOf("fetch")!==-1||m.indexOf("network")!==-1)return"Network error. Check connection.";return"Error: "+m.slice(0,80);}

// ── URL CACHE ─────────────────────────────────────────────────────────────────
function urlCacheKey(url){return"urlcache:"+btoa(url.trim()).replace(/[^a-zA-Z0-9]/g,"_").slice(0,100);}
async function getCached(url){
  try{const r=await window.storage.get(urlCacheKey(url));if(!r)return null;return JSON.parse(r.value);}catch(e){return null;}
}
async function setCached(url,payload){
  try{await window.storage.set(urlCacheKey(url),JSON.stringify({...payload,cachedAt:Date.now()}));}catch(e){}
}

// ── COMPRESSION ───────────────────────────────────────────────────────────────
const F={domNew:1,domYoung:2,badActor:4,noGlobal:8,retracted:16,conflict:32,clickbait:64,highRhet:128};
const POL_LABELS=["Far Left","Left","Ctr-Left","Center","Ctr-Right","Right","Far Right","Natl"];
const EPOCH=new Date("2024-01-01").getTime();
function daysNow(){return Math.floor((Date.now()-EPOCH)/86400000);}
function daysToDate(d){return new Date(EPOCH+d*86400000).toLocaleDateString();}
function flagsToStrings(f){const out=[];if(f&F.domNew)out.push("Domain<90d");if(f&F.domYoung)out.push("Domain<1yr");if(f&F.badActor)out.push("Bad actor");if(f&F.noGlobal)out.push("No coverage");if(f&F.retracted)out.push("Retracted");if(f&F.conflict)out.push("Conflict");if(f&F.clickbait)out.push("Clickbait");if(f&F.highRhet)out.push("High rhetoric");return out;}

function compress(r,url,osint,ci){
  const vs=(r.politicalLeanings?.values)||[];
  const ls=(r.politicalLeanings?.labels)||[];
  const mi=vs.indexOf(Math.max(...(vs.length?vs:[0])));
  const polIdx=Math.max(...(vs.length?vs:[0]))>20?POL_LABELS.indexOf(ls[mi]):3;
  let flags=0;
  if(osint?.whois){if(osint.whois.ageDays<90)flags|=F.domNew;else if(osint.whois.ageDays<365)flags|=F.domYoung;}
  if(osint?.openSources?.flagged)flags|=F.badActor;
  if(osint?.gdelt?.count===0)flags|=F.noGlobal;
  if(osint?.scholar?.some(p=>p.retracted))flags|=F.retracted;
  if(r.ownership?.conflictOfInterest)flags|=F.conflict;
  if(r.headline&&(r.headline.match==="CLICKBAIT"||r.headline.match==="MISLEADING"))flags|=F.clickbait;
  if(r.rhetoric?.some(x=>x.severity==="high"))flags|=F.highRhet;
  const pre=osint?osintPreScore(osint):null;
  return{v:2,d:domainName(url),t:daysNow(),s:r.overallScore,os:pre?pre.score:null,p:polIdx>=0?polIdx:3,f:flags,
    q:r.criteria?.factCheck?.score??null,h:r.headline?r.headline.score:null,
    ow:r.ownership?.chain?.[0]?.name.slice(0,24)??null,
    gd:osint?.gdelt?.count??null,wa:osint?.whois?.ageDays??null,
    cs:(r.claims||[]).slice(0,5).map(c=>c.score),sum:r.summary?r.summary.slice(0,120):null,
    ci:ci?{lo:ci.low,hi:ci.high}:null};
}

// ── OSINT ─────────────────────────────────────────────────────────────────────
function withTimeout(promise,ms){return Promise.race([promise,new Promise((_,reject)=>setTimeout(()=>reject(new Error("timeout")),ms))]);}

async function queryGDELT(url){
  try{const domain=new URL(url).hostname.replace("www.","");const q=encodeURIComponent('"'+domain+'"');
  const r=await withTimeout(fetch("https://api.gdeltproject.org/api/v2/doc/doc?query="+q+"&mode=artlist&maxrecords=10&format=json"),6000);
  if(!r.ok)return null;const d=await r.json();const articles=d.articles||[];
  const sources=[];articles.forEach(a=>{if(!sources.includes(a.domain))sources.push(a.domain);});
  return{count:articles.length,sources:sources.slice(0,5),raw:articles.slice(0,3)};}catch(e){return null;}
}
async function queryWHOIS(url){
  try{const domain=new URL(url).hostname.replace("www.","");
  const r=await withTimeout(fetch("https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_demo&domainName="+domain+"&outputFormat=JSON"),5000);
  if(!r.ok)return null;const d=await r.json();const wr=d.WhoisRecord||{};
  const created=wr.createdDate||(wr.registryData&&wr.registryData.createdDate);if(!created)return null;
  const ageDays=Math.floor((Date.now()-new Date(created).getTime())/86400000);
  return{ageDays,ageYears:(ageDays/365).toFixed(1),created:created.slice(0,10),registrar:wr.registrarName||"Unknown"};}catch(e){return null;}
}
const KNOWN_BAD=new Set(["infowars.com","naturalnews.com","beforeitsnews.com","worldnewsdailyreport.com","empirenews.net","nationalreport.net","theonion.com","clickhole.com","babylonbee.com","zerohedge.com","globalresearch.ca","activistpost.com","21stcenturywire.com","thegatewaypundit.com","bigleaguepolitics.com","coreysdigs.com","veteranstoday.com"]);
async function checkOpenSources(url){
  try{const domain=new URL(url).hostname.replace("www.","");const base=domain.split(".").slice(-2).join(".");return{domain:base,flagged:KNOWN_BAD.has(domain)||KNOWN_BAD.has(base)};}catch(e){return null;}
}
async function checkSemanticScholar(query){
  try{const r=await withTimeout(fetch("https://api.semanticscholar.org/graph/v1/paper/search?query="+encodeURIComponent(query.slice(0,200))+"&fields=title,year,citationCount,isRetracted,authors&limit=3"),6000);
  if(!r.ok)return null;const d=await r.json();
  return(d.data||[]).map(p=>({title:p.title,year:p.year,citations:p.citationCount,retracted:p.isRetracted,authors:(p.authors||[]).slice(0,2).map(a=>a.name).join(", ")}));}catch(e){return null;}
}
async function queryGDELTTone(keywords){
  try{const r=await withTimeout(fetch("https://api.gdeltproject.org/api/v2/doc/doc?query="+encodeURIComponent(keywords.slice(0,100))+"&mode=tonechart&format=json"),5000);
  if(!r.ok)return null;const d=await r.json();const bins=d.tonechart||[];if(!bins.length)return null;
  const avg=bins.reduce((s,b)=>s+parseFloat(b.tonescore||0),0)/bins.length;return{avgTone:avg.toFixed(2)};}catch(e){return null;}
}
async function queryFactCheckTools(url){
  try{const domain=new URL(url).hostname.replace("www.","");
  const r=await withTimeout(fetch("https://factchecktools.googleapis.com/v1alpha1/claims:search?query="+encodeURIComponent(domain)+"&key=AIzaSyDemo_FactCheckAPI_NotReal"),4000);
  if(!r.ok)return null;const d=await r.json();
  return(d.claims||[]).slice(0,5).map(c=>{const rv=(c.claimReview&&c.claimReview[0])||{};return{claim:c.text,claimant:c.claimant,date:c.claimDate,publisher:rv.publisher?.name,rating:rv.textualRating,url:rv.url};});}catch(e){return null;}
}
async function queryWayback(url){
  try{const encoded=encodeURIComponent(url);
  const avail=await withTimeout(fetch("https://archive.org/wayback/available?url="+encoded),5000);
  if(!avail.ok)return null;const ad=await avail.json();
  const closest=ad.archived_snapshots?.closest;if(!closest?.available)return{available:false};
  const snapTs=closest.timestamp;
  const snapDate=snapTs.slice(0,4)+"-"+snapTs.slice(4,6)+"-"+snapTs.slice(6,8);
  const snapUrl=closest.url;
  let firstSeen=null;
  try{const cdxR=await withTimeout(fetch("https://web.archive.org/cdx/search/cdx?url="+encoded+"&output=json&limit=1&fl=timestamp&from=20000101"),4000);
  if(cdxR.ok){const cdx=await cdxR.json();if(cdx?.length>1){const ts=cdx[1][0];firstSeen=ts.slice(0,4)+"-"+ts.slice(4,6)+"-"+ts.slice(6,8);}}}catch(e){}
  let certAge=null;
  try{const domain=new URL(url).hostname.replace("www.","");
  const crtR=await withTimeout(fetch("https://crt.sh/?q="+domain+"&output=json"),4000);
  if(crtR.ok){const certs=await crtR.json();if(certs?.length){const earliest=certs.reduce((min,c)=>c.not_before<min?c.not_before:min,certs[0].not_before);certAge=earliest?earliest.slice(0,10):null;}}}catch(e){}
  return{available:true,latestSnapshot:snapDate,latestUrl:snapUrl,firstSeen,certAge};}catch(e){return null;}
}

function osintPreScore(osint){
  if(!osint)return null;let score=65;const flags=[];
  if(osint.whois){if(osint.whois.ageDays<90){score-=30;flags.push("Domain<90 days");}else if(osint.whois.ageDays<365){score-=15;flags.push("Domain<1 year");}else if(osint.whois.ageDays>3650)score+=10;}
  if(osint.openSources?.flagged){score-=35;flags.push("Known unreliable");}
  if(osint.gdelt){if(osint.gdelt.count===0){score-=20;flags.push("No global coverage");}else if(osint.gdelt.count>5)score+=15;}
  if(osint.scholar?.some(p=>p.retracted)){score-=25;flags.push("Retracted citation");}
  if(osint.tone){const t=parseFloat(osint.tone.avgTone);if(t<-5){score-=10;flags.push("Negative sentiment");}if(t>5){score-=5;flags.push("Suspicious positivity");}}
  if(osint.wayback){if(!osint.wayback.available){score-=8;flags.push("No archive record");}
  if(osint.wayback.certAge&&osint.wayback.firstSeen){const cy=parseInt(osint.wayback.certAge.slice(0,4));const ay=parseInt(osint.wayback.firstSeen.slice(0,4));if(cy>ay+2){score-=12;flags.push("Cert newer than archive");}}}
  if(osint.factChecks?.length>0){const neg=["false","mostly false","pants on fire","four pinocchios","misleading"];
  if(osint.factChecks.some(c=>c.rating&&neg.some(n=>c.rating.toLowerCase().includes(n)))){score-=20;flags.push("Fact-checked as false");}}
  return{score:Math.max(0,Math.min(100,score)),flags};
}
function computeConfidenceInterval(aiScore,osint){
  const pre=osintPreScore(osint);const signals=[aiScore];
  if(pre?.score!=null)signals.push(pre.score);
  if(osint?.gdelt){if(osint.gdelt.count>5)signals.push(Math.min(100,aiScore+10));else if(osint.gdelt.count===0)signals.push(Math.max(0,aiScore-20));}
  if(osint?.openSources?.flagged)signals.push(Math.max(0,aiScore-30));
  const avg=signals.reduce((s,v)=>s+v,0)/signals.length;
  const variance=signals.reduce((s,v)=>s+Math.pow(v-avg,2),0)/signals.length;
  const stdDev=Math.sqrt(variance);
  const agreement=stdDev<10?"HIGH":stdDev<20?"MEDIUM":"LOW";
  return{low:Math.max(0,Math.round(avg-stdDev)),high:Math.min(100,Math.round(avg+stdDev)),stdDev:Math.round(stdDev),agreement,signalCount:signals.length};
}
async function runOSINT(url){
  let domain="";try{domain=new URL(url).hostname.replace("www.","");}catch(e){}
  const results=await Promise.all([queryGDELT(url),queryWHOIS(url),checkOpenSources(url),checkSemanticScholar(domain),queryGDELTTone(domain),queryFactCheckTools(url),queryWayback(url)]);
  return{gdelt:results[0],whois:results[1],openSources:results[2],scholar:results[3],tone:results[4],factChecks:results[5],wayback:results[6]};
}

// ── SOCIAL ────────────────────────────────────────────────────────────────────
const SOCIAL_DOMAINS=new Set(["x.com","twitter.com","t.co","instagram.com","facebook.com","threads.net","bsky.app","tiktok.com"]);
const SOCIAL_NAMES={"x.com":"X / Twitter","twitter.com":"X / Twitter","t.co":"X / Twitter","instagram.com":"Instagram","facebook.com":"Facebook","threads.net":"Threads","bsky.app":"Bluesky","tiktok.com":"TikTok"};
function isSocialUrl(url){try{return SOCIAL_DOMAINS.has(new URL(url.trim()).hostname.replace("www.",""));}catch(e){return false;}}
function sanitizeSocial(raw){
  if(!raw||typeof raw!=="object")return null;
  return{
    platform:String(raw.platform||"Social Media").slice(0,40),
    author:String(raw.author||"Unknown").slice(0,80),
    authorVerified:!!raw.authorVerified,
    authorFollowers:String(raw.authorFollowers||"Unknown").slice(0,30),
    authorAccountAge:String(raw.authorAccountAge||"Unknown").slice(0,30),
    authorCredibility:Math.max(0,Math.min(100,parseInt(raw.authorCredibility)||50)),
    postText:String(raw.postText||"").slice(0,600),
    postType:["FACT_CLAIM","OPINION","SATIRE","HUMOR","NEWS_SHARE","MISINFORMATION","UNKNOWN"].includes(raw.postType)?raw.postType:"UNKNOWN",
    isOpinion:!!raw.isOpinion,
    claimsMade:Array.isArray(raw.claimsMade)?raw.claimsMade.slice(0,6).map(c=>String(c).slice(0,200)):[],
    imagesPresent:!!raw.imagesPresent,
    imageAnalysis:String(raw.imageAnalysis||"").slice(0,400),
    linkedSources:Array.isArray(raw.linkedSources)?raw.linkedSources.slice(0,5).map(s=>String(s).slice(0,300)).filter(s=>isValidUrl(s)):[],
    sourceCredibility:String(raw.sourceCredibility||"").slice(0,300),
    claimVerification:String(raw.claimVerification||"").slice(0,400),
    context:String(raw.context||"").slice(0,300),
    viralRisk:["HIGH","MEDIUM","LOW"].includes(raw.viralRisk)?raw.viralRisk:"MEDIUM",
    viralReason:String(raw.viralReason||"").slice(0,200),
    overallVerdict:String(raw.overallVerdict||"").slice(0,400),
    truthScore:Math.max(0,Math.min(100,parseInt(raw.truthScore)||50)),
    opinionScore:Math.max(0,Math.min(100,parseInt(raw.opinionScore)||50)),
    confidence:["HIGH","MEDIUM","LOW"].includes(raw.confidence)?raw.confidence:"MEDIUM",
  };
}
const SOCIAL_SYS=`You are an expert social media fact-checker. Analyze the given social media post URL using web search. Return ONLY valid JSON, no markdown:
{"platform":"<n>","author":"<@handle>","authorVerified":<bool>,"authorFollowers":"<count>","authorAccountAge":"<age>","authorCredibility":<0-100>,"postText":"<text up to 300 chars>","postType":"FACT_CLAIM|OPINION|SATIRE|HUMOR|NEWS_SHARE|MISINFORMATION|UNKNOWN","isOpinion":<bool>,"claimsMade":["<factual claim>"],"imagesPresent":<bool>,"imageAnalysis":"<desc>","linkedSources":["<url>"],"sourceCredibility":"<1 sentence>","claimVerification":"<do claims appear in verifiable sources?>","context":"<context>","viralRisk":"HIGH|MEDIUM|LOW","viralReason":"<why>","overallVerdict":"<1-2 sentence verdict>","truthScore":<0-100>,"opinionScore":<0-100>,"confidence":"HIGH|MEDIUM|LOW"}`;

async function analyzeSocialPost(url){
  try{
    const uMsg="Analyze this social media post — find the content, images, author details, and fact-check any specific claims: "+url;
    const s1=await withTimeout(fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:1500,system:SOCIAL_SYS,tools:[{type:"web_search_20250305",name:"web_search"}],messages:[{role:"user",content:uMsg}]})}),25000);
    if(!s1.ok)return null;const d1=await s1.json();if(d1.error)return null;
    const s2=await withTimeout(fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:1500,system:SOCIAL_SYS,messages:[{role:"user",content:uMsg},{role:"assistant",content:d1.content},{role:"user",content:"Output ONLY the JSON object."}]})}),15000);
    if(!s2.ok)return null;const d2=await s2.json();
    const txt=(d2.content||[]).filter(b=>b.type==="text").map(b=>b.text).join("").replace(/```json\n?|```\n?/g,"").trim();
    const m=txt.match(/\{[\s\S]*\}/);if(!m)return null;
    return sanitizeSocial(JSON.parse(m[0]));
  }catch(e){return null;}
}

function domainName(url){try{return new URL(url).hostname.replace("www.","");}catch(e){return url;}}
function domainKey(url){return"rep:"+domainName(url).replace(/[^\w.-]/g,"_");}
async function saveRep(r,url,osint,ci){
  try{
    const key=domainKey(url),rec=compress(r,url,osint,ci);
    const prev=await window.storage.get(key).catch(()=>null);
    const hist=prev?JSON.parse(prev.value):[];
    hist.unshift(rec);if(hist.length>20)hist.length=20;
    await window.storage.set(key,JSON.stringify(hist));
    const idxRaw=await window.storage.get("idx",true).catch(()=>null);
    const idx=idxRaw?JSON.parse(idxRaw.value):{};
    idx[rec.d]={s:rec.s,os:rec.os,t:rec.t,p:rec.p,f:rec.f,gd:rec.gd,wa:rec.wa,ci:rec.ci};
    await window.storage.set("idx",JSON.stringify(idx),true);
    Object.defineProperty(window,"__TRUTHILIZER_INDEX__",{value:Object.freeze(JSON.parse(JSON.stringify(idx))),configurable:true,writable:false});
  }catch(e){console.warn("storage:",e);}
}
async function loadIdx(){try{const r=await window.storage.get("idx",true);return r?JSON.parse(r.value):{};}catch(e){return{};}}
async function loadHist(d){try{const r=await window.storage.get("rep:"+d.replace(/[^\w.-]/g,"_"));return r?JSON.parse(r.value):[];}catch(e){return[];}}

// ── AUDIO ─────────────────────────────────────────────────────────────────────
function useAudio(){
  const state=useRef({actx:null,nodes:[],genre:null});
  const getCtx=useCallback(()=>{if(!state.current.actx||state.current.actx.state==="closed")state.current.actx=new(window.AudioContext||window.webkitAudioContext)();if(state.current.actx.state==="suspended")state.current.actx.resume();return state.current.actx;},[]);
  const mkOsc=useCallback((c,freq,type,s,e,vol)=>{const o=c.createOscillator(),g=c.createGain();o.type=type;o.frequency.value=freq;g.gain.setValueAtTime(vol||0.07,s);g.gain.exponentialRampToValueAtTime(0.0001,e);o.connect(g);g.connect(c.destination);o.start(s);o.stop(e);state.current.nodes.push(o);},[]);
  const mkNoise=useCallback((c,s,dur,vol)=>{const len=Math.floor(c.sampleRate*dur),buf=c.createBuffer(1,len,c.sampleRate),d=buf.getChannelData(0);for(let i=0;i<len;i++)d[i]=Math.random()*2-1;const src=c.createBufferSource(),g=c.createGain();g.gain.setValueAtTime(vol||0.05,s);g.gain.exponentialRampToValueAtTime(0.0001,s+dur);src.buffer=buf;src.connect(g);g.connect(c.destination);src.start(s);src.stop(s+dur);state.current.nodes.push(src);},[]);
  const stop=useCallback(()=>{state.current.nodes.forEach(n=>{try{n.stop();}catch(e){}});state.current.nodes=[];state.current.genre=null;},[]);
  const schedLoop=useCallback((genre,fn)=>{state.current.genre=genre;let t=getCtx().currentTime+0.05;function tick(){if(state.current.genre!==genre)return;t+=fn(t);setTimeout(tick,Math.max(50,(t-getCtx().currentTime)*1000-300));}tick();},[getCtx]);
  const play=useCallback((id)=>{stop();const c=getCtx();
    if(id==="lofi")schedLoop("lofi",t=>{const ch=[[261.6,329.6,392,493.9],[220,261.6,329.6,440],[174.6,220,261.6,349.2],[196,246.9,293.7,392]][Math.floor(Math.random()*4)];ch.forEach(f=>mkOsc(c,f,"triangle",t,t+2.3,0.05));mkOsc(c,ch[0]/2,"sine",t,t+1.8,0.11);[0,.25,.5,.75].forEach(off=>mkNoise(c,t+off,.04,.04));return 2.8;});
    if(id==="jazz")schedLoop("jazz",t=>{const v=[[293.7,370,440,554],[246.9,311.1,370,493.9],[261.6,329.6,415.3,523.3]][Math.floor(Math.random()*3)];[0,.4,.9,1.1,1.7,2.2].forEach((off,i)=>mkOsc(c,v[i%v.length]*(Math.random()>.7?2:1),i%2?"triangle":"sawtooth",t+off,t+off+.15+Math.random()*.2,.07));[0,.7,1.4,2.1].forEach((off,i)=>mkOsc(c,v[0]/2*(1+i*.125),"triangle",t+off,t+off+.6,.13));return 2.9;});
    if(id==="metal"){const ws=c.createWaveShaper(),master=c.createGain();const curve=new Float32Array(512);for(let i=0;i<512;i++){const x=i*2/512-1;curve[i]=x<0?-Math.pow(-x,.7):Math.pow(x,.7);}ws.curve=curve;ws.connect(master);master.gain.value=0.11;master.connect(c.destination);schedLoop("metal",t=>{const pc=[[82.4,123.5],[110,165],[146.8,220],[196,293.7]][Math.floor(Math.random()*4)];[1,0,1,1,0,1,0,1].forEach((hit,i)=>{if(!hit)return;pc.forEach(f=>{const o=c.createOscillator(),g=c.createGain();o.type="sawtooth";o.frequency.value=f;g.gain.setValueAtTime(.38,t+i*.12);g.gain.linearRampToValueAtTime(0,t+i*.12+.1);o.connect(g);g.connect(ws);o.start(t+i*.12);o.stop(t+i*.12+.13);state.current.nodes.push(o);});});[0,.48].forEach(off=>mkNoise(c,t+off,.12,.45));return .98;});}
  },[stop,getCtx,schedLoop,mkOsc,mkNoise]);
  const beep=useCallback((freq,dur,type,vol)=>{const c=getCtx();mkOsc(c,freq||660,type||"sine",c.currentTime,c.currentTime+(dur||.06),vol||.05);},[getCtx,mkOsc]);
  const chime=useCallback(score=>{const c=getCtx(),t=c.currentTime;(score>65?[523,659,784]:score>40?[440,554,659]:[220,277,330]).forEach((f,i)=>mkOsc(c,f,"sine",t+i*.1,t+i*.1+.5,.07));},[getCtx,mkOsc]);
  const hover=useCallback(freq=>{const c=getCtx();mkOsc(c,freq||440,"sine",c.currentTime,c.currentTime+.04,.025);},[getCtx,mkOsc]);
  const tick=useCallback(()=>beep(1200,.03,"sine",.03),[beep]);
  const api=useRef({play,stop,beep,chime,hover,tick});api.current={play,stop,beep,chime,hover,tick};return api;
}

// ── NEON ──────────────────────────────────────────────────────────────────────
function useNeon(color){
  const ref=useRef(null),tRef=useRef(Math.random()*Math.PI*2),rafRef=useRef(null);
  useEffect(()=>{
    const el=ref.current;if(!el)return;
    function tick(){tRef.current+=0.025;const t=tRef.current,p1=0.6+Math.sin(t*1.1)*0.4,p2=0.55+Math.sin(t*1.7+1.2)*0.45;
    const rgb=hexRgb(color),r=rgb[0],g=rgb[1],b=rgb[2];
    const c0=`rgba(${r},${g},${b},1)`,c1=`rgba(${r},${g},${b},${(p1*.95).toFixed(2)})`,c2=`rgba(${r},${g},${b},${(p2*.75).toFixed(2)})`,c3=`rgba(${r},${g},${b},${(p1*.45).toFixed(2)})`,c4=`rgba(${r},${g},${b},${(p2*.2).toFixed(2)})`;
    el.style.boxShadow=[`0 0 0 1px ${c0}`,`0 0 3px 1px ${c3}`,`0 0 9px 2px ${c2}`,`0 0 20px 4px ${c1}`,`0 0 40px 8px ${c4}`,`inset 0 0 8px 0 ${c4}`].join(", ");
    rafRef.current=requestAnimationFrame(tick);}
    rafRef.current=requestAnimationFrame(tick);
    return()=>cancelAnimationFrame(rafRef.current);
  },[color]);
  return ref;
}
function useNeonEdge(color){
  const ref=useRef(null),tRef=useRef(Math.random()*Math.PI*2),rafRef=useRef(null);
  useEffect(()=>{
    const el=ref.current;if(!el)return;
    function tick(){tRef.current+=0.025;const t=tRef.current,p=0.6+Math.sin(t*1.1)*0.4;const rgb=hexRgb(color),r=rgb[0],g=rgb[1],b=rgb[2];
    el.style.boxShadow=`0 1px 0 0 rgba(${r},${g},${b},1), 0 2px 8px 0 rgba(${r},${g},${b},${(p*.75).toFixed(2)}), 0 4px 18px 0 rgba(${r},${g},${b},${(p*.4).toFixed(2)})`;
    rafRef.current=requestAnimationFrame(tick);}
    rafRef.current=requestAnimationFrame(tick);
    return()=>cancelAnimationFrame(rafRef.current);
  },[color]);
  return ref;
}
function LiveBorder({color,style,children}){const ref=useNeon(color||P.teal);return <div ref={ref} style={{borderRadius:4,...style}}>{children}</div>;}
function NeonLine({color,mt}){const ref=useNeonEdge(color||P.teal);return <div ref={ref} style={{height:1,marginTop:mt||0,borderRadius:1}} />;}
const NeonDivider=memo(({color,mb,mt})=>{const ref=useNeon(color||P.border);return <div ref={ref} style={{height:1,marginBottom:mb||8,marginTop:mt||8,borderRadius:1}} />;});

// ── ATOMS ─────────────────────────────────────────────────────────────────────
const ScrambleText=memo(({text,active})=>{
  const [display,setDisplay]=useState(text);
  useEffect(()=>{
    if(!active){setDisplay(text);return;}
    let step=0;const iv=setInterval(()=>{step++;const progress=Math.min(1,step/18);let out="";
    for(let i=0;i<text.length;i++){if(text[i]===" "){out+=" ";continue;}out+=i/text.length<progress?text[i]:POOL[Math.floor(Math.random()*POOL.length)];}
    setDisplay(out);if(progress>=1)clearInterval(iv);},60);
    return()=>{clearInterval(iv);setDisplay(text);};
  },[active,text]);
  return <span>{display}</span>;
});
function SlideIn({children,delay}){
  const [v,setV]=useState(false);
  useEffect(()=>{const t=setTimeout(()=>setV(true),delay||0);return()=>clearTimeout(t);},[delay]);
  return <div style={{opacity:v?1:0,transform:v?"translateY(0)":"translateY(14px)",transition:"opacity 0.35s ease, transform 0.35s ease"}}>{children}</div>;
}
function AmbientGlow({score}){
  if(score===null)return null;
  const c=scoreColor(score),rgb=hexRgb(c);
  return <div style={{position:"fixed",inset:0,pointerEvents:"none",zIndex:0,background:`radial-gradient(ellipse at 50% 0%, rgba(${rgb[0]},${rgb[1]},${rgb[2]},0.09) 0%, transparent 60%)`,transition:"background 2s ease"}} />;
}
function FlashOverlay({show,color}){
  const [opacity,setOpacity]=useState(0);
  useEffect(()=>{if(!show)return;setOpacity(0.3);const t=setTimeout(()=>setOpacity(0),350);return()=>clearTimeout(t);},[show]);
  if(opacity===0)return null;
  return <div style={{position:"fixed",inset:0,background:color||P.teal,opacity,pointerEvents:"none",zIndex:999,transition:"opacity 0.35s ease"}} />;
}
function AnimatedScore({score}){
  const [val,setVal]=useState(0);
  useEffect(()=>{let cur=0;const step=Math.ceil(score/40);const iv=setInterval(()=>{cur=Math.min(score,cur+step);setVal(cur);if(cur>=score)clearInterval(iv);},22);return()=>clearInterval(iv);},[score]);
  return <span>{val}</span>;
}

// ── EYES ──────────────────────────────────────────────────────────────────────
const EYE_R=9,EYE_C=19;
const MASK=(()=>{const m=[],cx=(EYE_C-1)/2,cy=(EYE_R-1)/2;for(let r=0;r<EYE_R;r++)for(let c=0;c<EYE_C;c++){const dx=(c-cx)/cx,dy=(r-cy)/cy;if(dx*dx+dy*dy<=1)m.push([c,r]);}return m;})();
function Eyes({scoreRef}){
  const r1=useRef(null),r2=useRef(null),tRef=useRef(0);
  const grids=useRef([Array.from({length:EYE_R},()=>Array(EYE_C).fill(".")),Array.from({length:EYE_R},()=>Array(EYE_C).fill("."))]);
  useEffect(()=>{
    let raf;const CH=13,CW=8;const canvases=[r1.current,r2.current];const ctxs=canvases.map(c=>c.getContext("2d"));
    MASK.forEach(p=>{grids.current[0][p[1]][p[0]]=POOL[Math.floor(Math.random()*POOL.length)];grids.current[1][p[1]][p[0]]=POOL[Math.floor(Math.random()*POOL.length)];});
    canvases.forEach(c=>{c.width=EYE_C*CW;c.height=EYE_R*CH;});
    const blink={next:3+Math.random()*4,dur:.18,t:0};
    function draw(){
      tRef.current+=.004;const t=tRef.current;
      if(t>=blink.next){blink.t=t;blink.next=t+2.5+Math.random()*5;}
      const bp=t-blink.t,blinkP=(bp>=0&&bp<blink.dur)?Math.sin((bp/blink.dur)*Math.PI):0;
      const score=scoreRef.current,eyeCol=score!==null?scoreColor(score):P.teal;
      const rgb=hexRgb(eyeCol),er=rgb[0],eg=rgb[1],eb=rgb[2];
      const pupilCol=Math.round((EYE_C-1)/2+Math.sin(t)*.72*((EYE_C-1)/2-2)),pupilRow=Math.round((EYE_R-1)/2);
      canvases.forEach((canvas,ei)=>{
        const ctx=ctxs[ei];ctx.fillStyle=P.bg;ctx.fillRect(0,0,canvas.width,canvas.height);ctx.font=`600 ${CH-1}px ${M}`;
        MASK.forEach(p=>{
          const c=p[0],r=p[1],cx=(EYE_C-1)/2,cy=(EYE_R-1)/2;
          const dist=Math.sqrt(Math.pow((c-cx)/cx,2)+Math.pow((r-cy)/cy,2)),bright=1-dist*.6;
          const isPupil=Math.abs(c-pupilCol)<=1&&Math.abs(r-pupilRow)<=1,isIris=dist>.45&&dist<.82;
          const rowDist=Math.abs(r-(EYE_R-1)/2)/((EYE_R-1)/2),blinkHidden=blinkP>rowDist;
          let ch,col;
          if(blinkHidden){ch="-";col="rgba(168,200,232,0.25)";}
          else if(isPupil){ch="@";col=`rgba(${er},${eg},${eb},${(0.9+Math.sin(t*3)*.1).toFixed(2)})`;}
          else if(isIris){ch=POOL[Math.floor(Math.abs(Math.atan2(r-cy,c-cx)*10+t*2)%POOL.length)];col=`rgba(255,183,0,${(0.55+bright*.4).toFixed(2)})`;}
          else{if(Math.random()<.004)grids.current[ei][r][c]=POOL[Math.floor(Math.random()*POOL.length)];ch=grids.current[ei][r][c];col=`rgba(184,216,240,${(0.12+bright*.32).toFixed(2)})`;}
          ctx.fillStyle=col;ctx.fillText(ch,c*CW+2,r*CH+CH-2);
        });
      });
      raf=requestAnimationFrame(draw);
    }
    raf=requestAnimationFrame(draw);return()=>cancelAnimationFrame(raf);
  },[]);
  return <div><div style={{background:P.bg,padding:"20px 0 16px",display:"flex",justifyContent:"center",alignItems:"center",gap:52}}><canvas ref={r1} style={{imageRendering:"pixelated"}} /><canvas ref={r2} style={{imageRendering:"pixelated"}} /></div><NeonLine color={P.teal} /></div>;
}

// ── UI ATOMS ──────────────────────────────────────────────────────────────────
const NeonCell=memo(({color,style,pad,children})=>{const ref=useNeon(color||P.border);return <div ref={ref} style={{background:P.bg,borderRadius:3,padding:pad||"5px 8px",...style}}>{children}</div>;});
const Badge=memo(({color,text})=>{const c=color||P.teal,ref=useNeon(c);return <span ref={ref} style={{fontFamily:M,fontSize:8,background:c+"22",color:c,padding:"2px 7px",borderRadius:2,marginRight:4,marginBottom:3,display:"inline-block",letterSpacing:.5}}>{text}</span>;});
const Bar=memo(({score,h})=>{const c=scoreColor(score),ht=h||5,ref=useNeon(c);return <div style={{display:"flex",alignItems:"center",gap:8}}><div ref={ref} style={{flex:1,height:ht,background:P.bg,borderRadius:3,overflow:"hidden"}}><div style={{width:score+"%",height:"100%",background:c,borderRadius:3,transition:"width 1.2s cubic-bezier(.4,0,.2,1)"}} /></div><span style={{fontFamily:M,fontSize:10,color:c,minWidth:28,textAlign:"right"}}>{score}</span></div>;});
function SpectrumBar({labels,values}){
  if(!labels||!values)return null;
  const max=Math.max(...values),idx=values.indexOf(max),pct=(idx/(labels.length-1))*100,bc=pct<35?P.blue:pct>65?P.red:P.amber,ref=useNeon(bc);
  return <div><div ref={ref} style={{position:"relative",height:8,background:P.bg,borderRadius:4,overflow:"hidden",marginBottom:4}}>
    <div style={{position:"absolute",left:0,top:0,bottom:0,width:"33%",background:P.blue+"22"}} />
    <div style={{position:"absolute",left:"33%",top:0,bottom:0,width:"34%",background:P.amber+"22"}} />
    <div style={{position:"absolute",left:"67%",top:0,bottom:0,right:0,background:P.red+"22"}} />
    <div style={{position:"absolute",top:0,bottom:0,width:3,background:bc,borderRadius:2,left:`calc(${pct}% - 1px)`,transition:"left 1s"}} />
  </div><div style={{display:"flex",justifyContent:"space-between"}}><span style={{fontFamily:M,fontSize:7,color:P.blue}}>LEFT</span><span style={{fontFamily:M,fontSize:8,color:bc}}>{labels[idx]||"—"}</span><span style={{fontFamily:M,fontSize:7,color:P.red}}>RIGHT</span></div></div>;
}
const PANEL_BG=[P.panel,P.alt];
let panelIdx=0;
function ACard({color,style,title,children}){const bg=PANEL_BG[panelIdx++%2];return <LiveBorder color={color||P.border} style={{background:bg,borderRadius:4,marginBottom:6,...style}}><div style={{padding:"10px 14px"}}>{title&&<div style={{fontFamily:M,fontSize:8,color:P.dim,letterSpacing:2,marginBottom:8}}>{title}</div>}{children}</div></LiveBorder>;}
function Group({title,color,urgentCount,defaultOpen,audioRef,children}){
  const [open,setOpen]=useState(defaultOpen||false);
  const bc=urgentCount>0?P.red:color,bodyRef=useNeon(bc);
  return <div style={{marginBottom:10}}>
    <LiveBorder color={bc} style={{background:urgentCount>0?P.redD+"44":P.panel,borderRadius:open?"4px 4px 0 0":"4px"}}>
      <button onClick={()=>{if(audioRef)audioRef.current.hover(open?330:440);setOpen(o=>!o);}} style={{width:"100%",background:"transparent",border:"none",padding:"12px 14px",cursor:"pointer",display:"flex",justifyContent:"space-between",alignItems:"center",fontFamily:M,fontSize:10,color:bc,letterSpacing:2}}>
        <span>{urgentCount>0?"⚠ ":""}{title}</span>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          {urgentCount>0&&<span style={{fontFamily:M,fontSize:8,background:P.red+"33",color:P.red,padding:"2px 8px",borderRadius:2,boxShadow:`0 0 8px 2px rgba(255,34,85,0.5)`}}>{urgentCount} FLAG{urgentCount>1?"S":""}</span>}
          <span style={{fontSize:11,color:P.dim}}>{open?"▲":"▼"}</span>
        </div>
      </button>
    </LiveBorder>
    {open&&<div ref={bodyRef} style={{borderRadius:"0 0 4px 4px",padding:"14px",background:P.alt}}>{children}</div>}
  </div>;
}
function Sub({title,color,urgent,audioRef,children}){
  const [open,setOpen]=useState(urgent||false);
  const c=urgent?P.red:(color||P.dim),ref=useNeon(c);
  return <div style={{marginBottom:6}}>
    <div ref={ref} style={{borderRadius:open?"4px 4px 0 0":"4px",overflow:"hidden"}}>
      <button onClick={()=>{if(audioRef)audioRef.current.hover(open?280:380);setOpen(o=>!o);}} style={{width:"100%",background:"transparent",border:"none",padding:"8px 10px",cursor:"pointer",display:"flex",justifyContent:"space-between",alignItems:"center",fontFamily:M,fontSize:9,color:c,letterSpacing:1,textAlign:"left"}}>
        <span>{urgent?"⚠ ":""}{title}</span>
        <span style={{fontSize:9,color:P.dim,marginLeft:8}}>{open?"▲":"▼"}</span>
      </button>
    </div>
    {open&&<div style={{paddingLeft:10,paddingTop:6}}>{children}</div>}
  </div>;
}
function TruthSegment({filled,col,delay}){const ref=useNeon(filled?col:P.border);return <div ref={ref} style={{flex:1,height:14,background:filled?col:P.bg,borderRadius:2,transition:`background ${delay}s`}} />;}

// ── VERDICT BADGE ─────────────────────────────────────────────────────────────
function VerdictFade({score}){
  const c=scoreColor(score),ref=useNeon(c);
  const label=score>65?"VERIFIED":score>40?"DEGRADED":"CORRUPTED";
  const sub=score>65?"Signal integrity nominal":"Signal interference detected";
  return <div ref={ref} style={{background:c+"18",borderRadius:4,padding:"8px 14px",marginBottom:8,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
    <span style={{fontFamily:M,fontSize:11,color:c,letterSpacing:4}}>◈ SIGNAL {label}</span>
    <span style={{fontFamily:M,fontSize:8,color:c+"aa",letterSpacing:1}}>{sub}</span>
  </div>;
}

// ── CONFIDENCE ────────────────────────────────────────────────────────────────
function ConfidenceBand({ci}){
  if(!ci)return null;
  const agreeColor=ci.agreement==="HIGH"?P.green:ci.agreement==="MEDIUM"?P.amber:P.red;
  const ref=useNeon(agreeColor);
  const mid=Math.round((ci.low+ci.high)/2);
  return <div ref={ref} style={{background:P.panel,borderRadius:4,padding:"10px 14px",marginBottom:8}}>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
      <span style={{fontFamily:M,fontSize:8,color:P.dim,letterSpacing:2}}>CONFIDENCE INTERVAL</span>
      <div style={{display:"flex",gap:10,alignItems:"center"}}>
        <span style={{fontFamily:M,fontSize:8,color:agreeColor}}>AGREEMENT: {ci.agreement}</span>
        <span style={{fontFamily:M,fontSize:8,color:P.dim}}>{ci.signalCount} signals</span>
      </div>
    </div>
    <div style={{position:"relative",height:20,background:P.bg,borderRadius:3,marginBottom:6}}>
      <div style={{position:"absolute",left:ci.low+"%",width:(ci.high-ci.low)+"%",top:0,bottom:0,background:agreeColor+"33",borderRadius:3,transition:"all 1s"}} />
      <div style={{position:"absolute",left:`calc(${mid}% - 1px)`,top:0,bottom:0,width:2,background:agreeColor,borderRadius:1,transition:"left 1s"}} />
    </div>
    <div style={{display:"flex",justifyContent:"space-between"}}>
      <span style={{fontFamily:M,fontSize:9,color:agreeColor}}>{ci.low}%</span>
      <span style={{fontFamily:M,fontSize:8,color:P.dim}}>±{ci.stdDev} pts</span>
      <span style={{fontFamily:M,fontSize:9,color:agreeColor}}>{ci.high}%</span>
    </div>
  </div>;
}

// ── SOCIAL PANEL ──────────────────────────────────────────────────────────────
function SocialPanel({social:s,audioRef}){
  if(!s)return null;
  const isOpinion=s.isOpinion||s.opinionScore>60;
  const accentColor=isOpinion?P.amber:s.truthScore>65?P.green:s.truthScore>40?P.amber:P.red;
  const typeColor={FACT_CLAIM:P.blue,OPINION:P.amber,SATIRE:P.purple,HUMOR:P.purple,NEWS_SHARE:P.teal,MISINFORMATION:P.red,UNKNOWN:P.dim}[s.postType]||P.dim;
  const viralColor=s.viralRisk==="HIGH"?P.red:s.viralRisk==="MEDIUM"?P.amber:P.green;
  return <Group title={"SOCIAL SIGNAL  ·  "+(s.platform||"SOCIAL")} color={P.pink} urgentCount={(!isOpinion&&s.truthScore<40)?1:0} defaultOpen audioRef={audioRef}>
    <div style={{display:"flex",gap:6,marginBottom:10,flexWrap:"wrap",alignItems:"center"}}>
      <Badge text={s.postType||"UNKNOWN"} color={typeColor}/>
      {isOpinion&&<Badge text="OPINION — not a fact claim" color={P.amber}/>}
      <Badge text={"VIRAL RISK: "+(s.viralRisk||"?")} color={viralColor}/>
      <Badge text={"CONFIDENCE: "+(s.confidence||"?")} color={P.dim}/>
    </div>
    <Sub title={"Author  ·  "+(s.author||"Unknown")} color={scoreColor(s.authorCredibility||50)} audioRef={audioRef}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginTop:6}}>
        {[{l:"HANDLE",v:s.author||"Unknown"},{l:"VERIFIED",v:s.authorVerified?"Yes":"No"},{l:"FOLLOWERS",v:s.authorFollowers||"Unknown"},{l:"ACCT AGE",v:s.authorAccountAge||"Unknown"}].map(item=><NeonCell key={item.l} color={P.border}><div style={{fontFamily:M,fontSize:7,color:P.dim,marginBottom:2}}>{item.l}</div><div style={{fontFamily:M,fontSize:9,color:P.text}}>{item.v}</div></NeonCell>)}
      </div>
      <div style={{marginTop:8}}><div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:4,letterSpacing:1}}>AUTHOR CREDIBILITY</div><Bar score={s.authorCredibility||50}/></div>
    </Sub>
    {s.postText&&<Sub title="Post Content" color={P.teal} audioRef={audioRef}>
      <div style={{background:P.bg,borderRadius:3,padding:"8px 10px",marginTop:6,maxHeight:160,overflowY:"auto",borderLeft:`2px solid ${P.teal}`}}>
        <p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.9,whiteSpace:"pre-wrap"}}>"{s.postText}"</p>
      </div>
      {s.context&&<p style={{fontFamily:M,fontSize:9,color:P.dim,margin:"6px 0 0",lineHeight:1.6}}>{s.context}</p>}
    </Sub>}
    {s.imagesPresent&&<Sub title="Image Analysis" color={P.purple} audioRef={audioRef}>
      <p style={{fontFamily:M,fontSize:10,color:P.text,margin:"6px 0 0",lineHeight:1.7}}>{s.imageAnalysis||"Images present but could not be analyzed."}</p>
    </Sub>}
    {s.claimsMade?.length>0&&<Sub title={"Claims Made  ·  "+s.claimsMade.length+" identified"} color={isOpinion?P.amber:P.blue} audioRef={audioRef}>
      {isOpinion&&<p style={{fontFamily:M,fontSize:9,color:P.amber,margin:"0 0 8px",lineHeight:1.6}}>⚠ These appear to be opinions, not verifiable factual claims.</p>}
      {s.claimsMade.map((claim,i)=><div key={i}><p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.7}}>{"• "+claim}</p>{i<s.claimsMade.length-1&&<NeonDivider color={P.blue} mt={5} mb={5}/>}</div>)}
      {s.claimVerification&&<div style={{marginTop:8}}><NeonDivider color={P.blue} mt={0} mb={6}/><div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:4,letterSpacing:1}}>VERIFICATION</div><p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.7}}>{s.claimVerification}</p></div>}
    </Sub>}
    {s.linkedSources?.length>0&&<Sub title={"Linked Sources  ·  "+s.linkedSources.length} color={P.teal} audioRef={audioRef}>
      {s.linkedSources.map((src,i)=><div key={i} style={{marginBottom:4}}><a href={safeHref(src)} target="_blank" rel="noopener noreferrer" style={{fontFamily:M,fontSize:9,color:P.teal,textDecoration:"none"}}>{src} ↗</a></div>)}
      {s.sourceCredibility&&<p style={{fontFamily:M,fontSize:9,color:P.dim,margin:"6px 0 0",lineHeight:1.6}}>{s.sourceCredibility}</p>}
    </Sub>}
    <div style={{marginTop:10,display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
      <div><div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:4,letterSpacing:1}}>TRUTH SCORE</div><Bar score={s.truthScore}/></div>
      <div><div style={{fontFamily:M,fontSize:8,color:P.amber,marginBottom:4,letterSpacing:1}}>OPINION SCORE</div>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <div ref={useNeon(P.amber)} style={{flex:1,height:5,background:P.bg,borderRadius:3,overflow:"hidden"}}><div style={{width:s.opinionScore+"%",height:"100%",background:P.amber,borderRadius:3,transition:"width 1.2s cubic-bezier(.4,0,.2,1)"}}/></div>
          <span style={{fontFamily:M,fontSize:10,color:P.amber,minWidth:28,textAlign:"right"}}>{s.opinionScore}</span>
        </div>
      </div>
    </div>
    {s.overallVerdict&&<div style={{marginTop:10,background:P.bg,borderRadius:3,padding:"9px 12px",borderLeft:`2px solid ${accentColor}`}}>
      <div style={{fontFamily:M,fontSize:8,color:accentColor,marginBottom:4,letterSpacing:1}}>VERDICT</div>
      <p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.7}}>{s.overallVerdict}</p>
    </div>}
  </Group>;
}

// ── MUSIC PANEL ───────────────────────────────────────────────────────────────
function MusicPanel({audioRef,score}){
  const autoGenre=score===null?null:score>65?"lofi":score>40?"jazz":"metal";
  const [active,setActive]=useState(null);
  const prevAuto=useRef(null);
  useEffect(()=>{if(autoGenre&&autoGenre!==prevAuto.current){prevAuto.current=autoGenre;setActive(autoGenre);audioRef.current.play(autoGenre);}},[autoGenre]);
  const stations=[{id:"lofi",label:"LO-FI",color:P.teal},{id:"jazz",label:"JAZZ",color:P.amber},{id:"metal",label:"METAL",color:P.red}];
  function toggle(id){audioRef.current.beep();if(active===id){audioRef.current.stop();setActive(null);}else{audioRef.current.play(id);setActive(id);}}
  const st=stations.find(s=>s.id===active);
  return <ACard title="AUDIO CHANNEL" color={P.audio}>
    <div style={{display:"flex",gap:8,marginBottom:active?10:0}}>
      {stations.map(s=><button key={s.id} onClick={()=>toggle(s.id)} style={{flex:1,fontFamily:M,fontSize:9,padding:"8px 4px",background:active===s.id?s.color+"22":P.bg,color:active===s.id?s.color:P.dim,border:`1px solid ${active===s.id?s.color:P.border}`,borderRadius:3,cursor:"pointer",letterSpacing:1}}>{active===s.id?"▶ ":""}{s.label}</button>)}
    </div>
    {st&&<div style={{display:"flex",alignItems:"center",gap:8}}><div style={{display:"flex",gap:3,alignItems:"flex-end",height:14}}>{[.4,.7,1,.6,.8,.5,.9].map((h,i)=><div key={i} style={{width:3,background:st.color,borderRadius:1,height:(h*100)+"%",animation:`vu ${0.4+i*.11}s ease-in-out infinite alternate`}}/>)}</div><span style={{fontFamily:M,fontSize:8,color:st.color}}>{autoGenre?"AUTO → "+st.label:"STREAMING "+st.label}</span></div>}
  </ACard>;
}

// ── TRUTH METER ───────────────────────────────────────────────────────────────
function TruthMeter({score}){
  const c=scoreColor(score);
  return <LiveBorder color={c} style={{background:P.panel,borderRadius:4,marginBottom:8}}>
    <div style={{padding:"14px 16px"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:12}}>
        <span style={{fontFamily:M,fontSize:9,color:P.dim,letterSpacing:2}}>TRUTH INDEX</span>
        <span style={{fontFamily:M,fontSize:30,color:c}}><AnimatedScore score={score}/><span style={{fontSize:13}}>%</span></span>
      </div>
      <div style={{display:"flex",gap:2,marginBottom:10}}>{Array.from({length:25},(_,i)=>{const pct=((i+1)/25)*100,filled=pct<=score,col=pct>65?P.green:pct>40?P.amber:P.red;return <TruthSegment key={i} filled={filled} col={col} delay={0.3+i*0.03}/>;})}</div>
      <div style={{fontFamily:M,fontSize:10,color:c,letterSpacing:3,textAlign:"center"}}>{score>65?"SIGNAL VERIFIED":score>40?"SIGNAL DEGRADED":"SIGNAL CORRUPTED"}</div>
    </div>
  </LiveBorder>;
}

// ── SUMMARY CARD ──────────────────────────────────────────────────────────────
function SummaryCard({r,osint,ci}){
  const c=scoreColor(r.overallScore);
  const entries=Object.entries(r.criteria||{});
  const worst=entries.length?entries.sort((a,b)=>a[1].score-b[1].score)[0]:null;
  const LABELS={source:"Source",funding:"Funding",author:"Author",authorPay:"Who Pays",copyPaste:"Originality",study:"Study",academic:"Academic",factCheck:"Fact-Check"};
  const vs=(r.politicalLeanings?.values)||[];const ls=(r.politicalLeanings?.labels)||[];
  const mi=vs.indexOf(Math.max(...(vs.length?vs:[0])));
  const pre=osint?osintPreScore(osint):null;
  const tiles=[
    {label:"TRUTH SCORE",val:r.overallScore+"%",col:c},
    {label:"OSINT SIGNAL",val:pre?pre.score+"%":"—",col:pre?scoreColor(pre.score):P.dim},
    {label:"WORST FLAG",val:worst?(LABELS[worst[0]]||worst[0])+" ("+worst[1].score+")":"—",col:worst?scoreColor(worst[1].score):P.dim},
    {label:"POLITICAL",val:Math.max(...(vs.length?vs:[0]))>20?(ls[mi]||"—"):"Center",col:P.amber},
  ];
  return <LiveBorder color={c} style={{background:P.panel,borderRadius:4,marginBottom:8}}>
    <div style={{padding:"14px"}}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:8,marginBottom:12}}>
        {tiles.map(tile=><NeonCell key={tile.label} color={tile.col} pad="8px 10px"><div style={{fontFamily:M,fontSize:7,color:P.dim,marginBottom:4,letterSpacing:1}}>{tile.label}</div><div style={{fontFamily:M,fontSize:11,color:tile.col}}>{tile.val}</div></NeonCell>)}
      </div>
      <p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.9}}>{r.summary}</p>
    </div>
  </LiveBorder>;
}

// ── CACHE HIT BANNER ──────────────────────────────────────────────────────────
function CacheBanner({cachedAt,onReanalyze}){
  const ref=useNeon(P.orange);
  const age=Math.round((Date.now()-cachedAt)/60000);
  const label=age<1?"just now":age<60?`${age}m ago`:`${Math.round(age/60)}h ago`;
  return <div ref={ref} style={{background:P.orange+"15",borderRadius:4,padding:"9px 14px",marginBottom:8,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
    <span style={{fontFamily:M,fontSize:9,color:P.orange,letterSpacing:1}}>◈ CACHED RESULT  ·  analyzed {label}</span>
    <button onClick={onReanalyze} style={{fontFamily:M,fontSize:8,background:P.orange+"22",color:P.orange,border:`1px solid ${P.orange}`,borderRadius:3,padding:"3px 10px",cursor:"pointer",letterSpacing:1}}>RE-ANALYZE ↻</button>
  </div>;
}

// ── OSINT PANEL ───────────────────────────────────────────────────────────────
function OSINTPanel({osint,audioRef}){
  if(!osint)return null;
  const pre=osintPreScore(osint),urgent=pre&&pre.score<40;
  return <Group title="OSINT PRE-FLIGHT" color={P.purple} urgentCount={urgent?1:0} defaultOpen={urgent} audioRef={audioRef}>
    {pre&&<div style={{marginBottom:12}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:6}}>
        <span style={{fontFamily:M,fontSize:8,color:P.dim,letterSpacing:1}}>PRE-FLIGHT SIGNAL SCORE</span>
        <span style={{fontFamily:M,fontSize:18,color:scoreColor(pre.score)}}>{pre.score}</span>
      </div>
      <Bar score={pre.score}/>
      {pre.flags.length>0&&<div style={{marginTop:6}}>{pre.flags.map((f,i)=><Badge key={i} text={"⚠ "+f} color={P.red}/>)}</div>}
    </div>}
    {osint.whois&&<Sub title={"Domain Forensics  ·  Age: "+osint.whois.ageYears+" yrs"} color={osint.whois.ageDays<365?P.red:P.green} urgent={osint.whois.ageDays<90} audioRef={audioRef}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginTop:6}}>
        {[{l:"REGISTERED",v:osint.whois.created},{l:"AGE",v:osint.whois.ageYears+" years"},{l:"REGISTRAR",v:osint.whois.registrar},{l:"RISK",v:osint.whois.ageDays<90?"HIGH":osint.whois.ageDays<365?"MEDIUM":"LOW"}].map(item=><NeonCell key={item.l} color={P.border}><div style={{fontFamily:M,fontSize:7,color:P.dim,marginBottom:2}}>{item.l}</div><div style={{fontFamily:M,fontSize:9,color:P.text}}>{item.v||"—"}</div></NeonCell>)}
      </div>
    </Sub>}
    {osint.wayback&&<Sub title={"Wayback Machine  ·  "+(osint.wayback.available?"Archived":"Not Archived")} color={osint.wayback.available?P.teal:P.red} urgent={!osint.wayback.available} audioRef={audioRef}>
      {!osint.wayback.available?<p style={{fontFamily:M,fontSize:10,color:P.red,margin:"6px 0 0",lineHeight:1.7}}>No archive record found.</p>
      :<div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginTop:6}}>
        {[{l:"FIRST SEEN",v:osint.wayback.firstSeen||"Unknown"},{l:"LATEST SNAPSHOT",v:osint.wayback.latestSnapshot||"Unknown"},{l:"SSL CERT SINCE",v:osint.wayback.certAge||"Unknown"},{l:"CERT VS ARCHIVE",v:osint.wayback.certAge&&osint.wayback.firstSeen&&parseInt(osint.wayback.certAge.slice(0,4))>parseInt(osint.wayback.firstSeen.slice(0,4))+2?"MISMATCH ⚠":"OK"}].map(item=>{const warn=item.v?.includes("MISMATCH");return <NeonCell key={item.l} color={warn?P.red:P.border}><div style={{fontFamily:M,fontSize:7,color:P.dim,marginBottom:2}}>{item.l}</div><div style={{fontFamily:M,fontSize:9,color:warn?P.red:P.text}}>{item.v}</div></NeonCell>;})}
        {osint.wayback.latestUrl&&<div style={{gridColumn:"1/-1",marginTop:4}}><a href={safeHref(osint.wayback.latestUrl)} target="_blank" rel="noopener noreferrer" style={{fontFamily:M,fontSize:9,color:P.teal,textDecoration:"none"}}>View latest snapshot ↗</a></div>}
      </div>}
    </Sub>}
    {osint.factChecks?.length>0&&<Sub title={"Fact-Check Records  ·  "+osint.factChecks.length+" found"} color={P.pink} urgent={osint.factChecks.some(c=>{const neg=["false","mostly false","pants on fire","four pinocchios"];return c.rating&&neg.some(n=>c.rating.toLowerCase().includes(n));})} audioRef={audioRef}>
      {osint.factChecks.map((fc,i)=>{const neg=["false","mostly false","pants on fire","four pinocchios","misleading"];const isFalse=fc.rating&&neg.some(n=>fc.rating.toLowerCase().includes(n));return <div key={i}><div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:4}}><Badge text={fc.rating||"Checked"} color={isFalse?P.red:P.green}/>{fc.publisher&&<Badge text={fc.publisher} color={P.teal}/>}</div>{fc.claim&&<p style={{fontFamily:M,fontSize:9,color:P.text,margin:"0 0 4px",lineHeight:1.6}}>{fc.claim}</p>}{fc.url&&<a href={safeHref(fc.url)} target="_blank" rel="noopener noreferrer" style={{fontFamily:M,fontSize:8,color:P.teal,textDecoration:"none"}}>View ↗</a>}{i<osint.factChecks.length-1&&<NeonDivider color={P.pink} mt={6} mb={6}/>}</div>;})}
    </Sub>}
    {osint.gdelt&&<Sub title={"GDELT Coverage  ·  "+osint.gdelt.count+" global articles"} color={osint.gdelt.count===0?P.red:P.green} urgent={osint.gdelt.count===0} audioRef={audioRef}>
      {osint.gdelt.count===0?<p style={{fontFamily:M,fontSize:10,color:P.red,margin:"6px 0 0",lineHeight:1.7}}>No mainstream global coverage found.</p>
      :<div style={{marginTop:6}}><div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:4}}>SOURCES REPORTING</div>{osint.gdelt.sources.map((s,i)=><Badge key={i} text={s} color={P.teal}/>)}{osint.gdelt.raw.map((a,i)=><div key={i}><a href={safeHref(a.url)} target="_blank" rel="noopener noreferrer" style={{fontFamily:M,fontSize:9,color:P.teal,textDecoration:"none"}}>{a.title||a.url} ↗</a>{i<osint.gdelt.raw.length-1&&<NeonDivider color={P.teal} mt={5} mb={5}/>}</div>)}</div>}
    </Sub>}
    {osint.openSources&&<Sub title={"Source Reputation  ·  "+(osint.openSources.flagged?"FLAGGED":"CLEAR")} color={osint.openSources.flagged?P.red:P.green} urgent={osint.openSources.flagged} audioRef={audioRef}>
      <p style={{fontFamily:M,fontSize:10,color:osint.openSources.flagged?P.red:P.green,margin:"6px 0 0",lineHeight:1.7}}>{osint.openSources.flagged?"Domain found in known unreliable source database.":"Domain not in known unreliable source lists."}</p>
    </Sub>}
    {osint.scholar?.length>0&&<Sub title="Academic Citation Graph" color={P.blue} audioRef={audioRef}>
      {osint.scholar.map((p,i)=><div key={i}><div style={{display:"flex",gap:6,marginBottom:4,flexWrap:"wrap"}}>{p.retracted&&<Badge text="RETRACTED" color={P.red}/>}<Badge text={String(p.year||"?")} color={P.dim}/><Badge text={p.citations+" citations"} color={P.teal}/></div><p style={{fontFamily:M,fontSize:9,color:P.text,margin:0,lineHeight:1.6}}>{p.title}</p>{p.authors&&<p style={{fontFamily:M,fontSize:8,color:P.dim,margin:"3px 0 0"}}>{p.authors}</p>}{i<osint.scholar.length-1&&<NeonDivider color={P.blue} mt={7} mb={7}/>}</div>)}
    </Sub>}
    {osint.tone&&<Sub title={"Global Sentiment  ·  Avg: "+osint.tone.avgTone} color={parseFloat(osint.tone.avgTone)<-5?P.red:parseFloat(osint.tone.avgTone)>5?P.amber:P.green} audioRef={audioRef}>
      <p style={{fontFamily:M,fontSize:10,color:P.text,margin:"6px 0 0",lineHeight:1.7}}>{parseFloat(osint.tone.avgTone)<-5?"Highly negative global sentiment.":parseFloat(osint.tone.avgTone)>5?"Unusually positive — possible coordinated content.":"Neutral global sentiment."}</p>
    </Sub>}
  </Group>;
}

// ── RESULT GROUPS ─────────────────────────────────────────────────────────────
function SourceGroup({r,audioRef}){
  const crit=r.criteria||{};
  const keys=["source","funding","author","authorPay"],lmap={source:"Source Origin",funding:"Funding / Hosting",author:"Author History",authorPay:"Who Pays Author"};
  const flags=keys.filter(k=>crit[k]&&crit[k].score<40).length,ownerUrgent=!!(r.ownership?.conflictOfInterest);
  return <Group title="SOURCE" color={P.amber} urgentCount={flags+(ownerUrgent?1:0)} audioRef={audioRef}>
    {keys.map(key=>{const d=crit[key];if(!d)return null;return <Sub key={key} title={lmap[key]+"  "+d.score} color={scoreColor(d.score)} urgent={d.score<40} audioRef={audioRef}><Bar score={d.score}/><p style={{fontFamily:M,fontSize:10,color:P.text,margin:"6px 0 0",lineHeight:1.7}}>{d.summary}</p>{(d.flags||[]).map((f,i)=><Badge key={i} text={"⚠ "+f} color={P.red}/>)}</Sub>;})}
    {r.ownership&&<Sub title={"Ownership Tree"+(ownerUrgent?" ⚠":"")} color={P.amber} urgent={ownerUrgent} audioRef={audioRef}>
      {(r.ownership.chain||[]).map((n,i)=><div key={i} style={{display:"flex",gap:8,marginBottom:5,alignItems:"center"}}><span style={{fontFamily:M,fontSize:8,color:P.dim}}>{Array(i+1).join("  ")}{"└─"}</span><NeonCell color={P.amber} style={{flex:1}} pad="5px 8px"><span style={{fontFamily:M,fontSize:9,color:P.amber}}>{n.name}</span>{n.note&&<span style={{fontFamily:M,fontSize:8,color:P.dim,marginLeft:8}}>{n.note}</span>}</NeonCell></div>)}
      {ownerUrgent&&<p style={{fontFamily:M,fontSize:9,color:P.red,margin:"6px 0 0",lineHeight:1.7}}>⚠ {r.ownership.conflictOfInterest}</p>}
    </Sub>}
  </Group>;
}
function ContentGroup({r,audioRef}){
  const claimU=r.claims?.some(c=>c.score<40)?1:0,headU=((r.headline?.score)||100)<40?1:0,rhetU=r.rhetoric?.some(x=>x.severity==="high")?1:0,missU=(r.missingContext?.length>1)?1:0;
  return <Group title="CONTENT" color={P.teal} urgentCount={claimU+headU+rhetU+missU} audioRef={audioRef}>
    {r.claims?.length>0&&<Sub title="Claim Extraction" color={P.teal} urgent={claimU>0} audioRef={audioRef}>
      {r.claims.map((claim,i)=><div key={i}><div style={{display:"flex",gap:8,alignItems:"flex-start",marginBottom:4}}><span style={{fontFamily:M,fontSize:8,color:P.dim,minWidth:16}}>{"#"+(i+1)}</span><p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,flex:1,lineHeight:1.7}}>{claim.claim}</p><span style={{fontFamily:M,fontSize:10,color:scoreColor(claim.score),minWidth:26,textAlign:"right"}}>{claim.score}</span></div><Bar score={claim.score}/><p style={{fontFamily:M,fontSize:9,color:P.dim,margin:"4px 0 0 24px",lineHeight:1.6}}>{claim.verdict}</p>{i<r.claims.length-1&&<NeonDivider color={P.teal} mt={8} mb={8}/>}</div>)}
    </Sub>}
    {r.headline&&<Sub title={"Headline vs Content  "+r.headline.score} color={scoreColor(r.headline.score)} urgent={headU>0} audioRef={audioRef}><Bar score={r.headline.score}/><div style={{marginTop:6,marginBottom:6}}><Badge text={r.headline.match} color={scoreColor(r.headline.score)}/>{(r.headline.flags||[]).map((f,i)=><Badge key={i} text={f} color={P.red}/>)}</div><p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.7}}>{r.headline.analysis}</p></Sub>}
    {r.rhetoric?.length>0&&<Sub title="Rhetoric & Fallacies" color={P.purple} urgent={rhetU>0} audioRef={audioRef}>
      {r.rhetoric.map((f,i)=>{const fc=f.severity==="high"?P.red:f.severity==="medium"?P.amber:P.teal;return <div key={i}><Badge text={f.type} color={fc}/><Badge text={f.severity.toUpperCase()} color={fc}/>{f.excerpt&&<p style={{fontFamily:M,fontSize:9,color:P.dim,margin:"4px 0",fontStyle:"italic",lineHeight:1.6}}>"{f.excerpt}"</p>}<p style={{fontFamily:M,fontSize:10,color:P.text,margin:"4px 0 0",lineHeight:1.7}}>{f.explanation}</p>{i<r.rhetoric.length-1&&<NeonDivider color={fc} mt={8} mb={8}/>}</div>;})}
    </Sub>}
    {r.missingContext?.length>0&&<Sub title="Missing Context" color={P.amber} urgent={missU>0} audioRef={audioRef}>
      {r.missingContext.map((m,i)=><div key={i}><Badge text={m.type} color={P.amber}/><p style={{fontFamily:M,fontSize:10,color:P.text,margin:"5px 0 0",lineHeight:1.7}}>{m.description}</p>{i<r.missingContext.length-1&&<NeonDivider color={P.amber} mt={6} mb={6}/>}</div>)}
    </Sub>}
  </Group>;
}
function ContextGroup({r,audioRef}){
  const consU=r.consensus?.overallPattern==="fringe"?1:0,tempU=r.temporal?.riskLevel==="high"?1:0;
  const ls=(r.interestGroups?.labels)||[],vs=(r.interestGroups?.values)||[];
  const topI=ls.map((l,i)=>({l,v:vs[i]||0})).sort((a,b)=>b.v-a.v).slice(0,4).filter(x=>x.v>10);
  const lmap2={source:"SRC",funding:"FND",author:"AUT",authorPay:"PAY",copyPaste:"ORI",study:"STD",academic:"ACA",factCheck:"FCK"};
  return <Group title="CONTEXT" color={P.blue} urgentCount={consU+tempU} audioRef={audioRef}>
    {r.consensus&&<Sub title="Consensus Map" color={P.blue} urgent={consU>0} audioRef={audioRef}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:6,marginBottom:8}}>
        {[{l:"HIGH CRED",v:r.consensus.highCred,c:P.green},{l:"LOW CRED",v:r.consensus.lowCred,c:P.red},{l:"ECHO ONLY",v:r.consensus.echoOnly,c:P.amber}].map(item=><NeonCell key={item.l} color={item.c} style={{textAlign:"center"}}><div style={{fontFamily:M,fontSize:16,color:item.c}}>{item.v}</div><div style={{fontFamily:M,fontSize:7,color:P.dim,marginTop:2}}>{item.l}</div></NeonCell>)}
      </div>
      <p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.7}}>{r.consensus.summary}</p>
    </Sub>}
    {r.temporal&&<Sub title="Temporal Analysis" color={P.blue} urgent={tempU>0} audioRef={audioRef}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:8}}>
        {[{l:"PUBLISHED",v:r.temporal.published},{l:"PATTERN",v:r.temporal.circulationPattern}].map(item=><NeonCell key={item.l} color={P.border}><div style={{fontFamily:M,fontSize:7,color:P.dim,marginBottom:2}}>{item.l}</div><div style={{fontFamily:M,fontSize:9,color:P.text}}>{item.v||"—"}</div></NeonCell>)}
      </div>
      <p style={{fontFamily:M,fontSize:10,color:P.text,margin:0,lineHeight:1.7}}>{r.temporal.summary}</p>
      {(r.temporal.corrections||[]).map((c,i)=><Badge key={i} text={"CORRECTION: "+c} color={P.red}/>)}
    </Sub>}
    {r.similarArticles?.length>0&&<Sub title="Similar Articles" color={P.teal} audioRef={audioRef}>
      {r.similarArticles.map((a,i)=><div key={i}><Badge text={a.credibility} color={a.credibility==="HIGH"?P.green:a.credibility==="MED"?P.amber:P.red}/><Badge text={a.outlet} color={P.teal}/><p style={{fontFamily:M,fontSize:10,color:P.text,margin:"4px 0 2px",lineHeight:1.7}}>{a.headline}</p><p style={{fontFamily:M,fontSize:9,color:P.dim,margin:0,lineHeight:1.6}}>{a.framingNote}</p>{i<r.similarArticles.length-1&&<NeonDivider color={P.teal} mt={6} mb={6}/>}</div>)}
    </Sub>}
    <Sub title="Bias Mapping" color={P.purple} audioRef={audioRef}>
      <div style={{marginBottom:10}}><div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:6,letterSpacing:1}}>POLITICAL SPECTRUM</div><SpectrumBar labels={r.politicalLeanings?.labels} values={r.politicalLeanings?.values}/></div>
      {topI.length>0&&<div><div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:6,letterSpacing:1}}>TOP INTEREST VECTORS</div>{topI.map(item=><div key={item.l} style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}><span style={{fontFamily:M,fontSize:9,color:P.text,minWidth:80}}>{item.l}</span><div style={{flex:1,height:4,background:P.bg,borderRadius:2,overflow:"hidden"}}><div style={{width:item.v+"%",height:"100%",background:P.teal,transition:"width 1s"}}/></div><span style={{fontFamily:M,fontSize:9,color:P.teal,minWidth:24,textAlign:"right"}}>{item.v}</span></div>)}</div>}
    </Sub>
    <Sub title="Subsystem Detail" color={P.dim} audioRef={audioRef}>
      {["source","funding","author","authorPay","copyPaste","study","academic","factCheck"].map(key=>{const d=r.criteria?.[key];if(!d)return null;return <div key={key} style={{display:"flex",alignItems:"center",gap:8,marginBottom:5}}><span style={{fontFamily:M,fontSize:8,color:P.dim,minWidth:28}}>{lmap2[key]}</span><div style={{flex:1}}><Bar score={d.score} h={4}/></div></div>;})}
    </Sub>
  </Group>;
}
function ResearchSection({r,audioRef}){
  if(!r.researchQueries?.length)return null;
  return <Group title="RESEARCH PATH  ·  VERIFY YOURSELF" color={P.green} urgentCount={0} audioRef={audioRef}>
    <p style={{fontFamily:M,fontSize:9,color:P.dim,margin:"0 0 10px",lineHeight:1.7}}>Tap any query to open an independent search.</p>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
      {r.researchQueries.map((q,i)=>(
        <a key={i} href={safeHref(q.url)} target="_blank" rel="noopener noreferrer" onClick={()=>audioRef?.current.tick()} style={{display:"block",textDecoration:"none"}}><NeonCell color={P.green} pad="8px 10px"><div style={{marginBottom:3}}><Badge text={q.type} color={P.green}/></div><p style={{fontFamily:M,fontSize:9,color:P.green,margin:0,lineHeight:1.6}}>{q.query} ↗</p></NeonCell></a>
      ))}
    </div>
  </Group>;
}

function Results({r,osint,ci,social,audioRef,fromCache,cachedAt,onReanalyze}){
  const [phase,setPhase]=useState(0);
  useEffect(()=>{const t1=setTimeout(()=>setPhase(1),300),t2=setTimeout(()=>setPhase(2),700);return()=>{clearTimeout(t1);clearTimeout(t2);};},[]);
  return <div>
    {fromCache&&<CacheBanner cachedAt={cachedAt} onReanalyze={onReanalyze}/>}
    <SlideIn delay={0}><TruthMeter score={r.overallScore}/></SlideIn>
    <SlideIn delay={0}><VerdictFade score={r.overallScore}/></SlideIn>
    <SlideIn delay={100}><ConfidenceBand ci={ci}/></SlideIn>
    {phase>=1&&<SlideIn delay={0}><SummaryCard r={r} osint={osint} ci={ci}/></SlideIn>}
    {phase>=2&&<div>
      {social&&<SlideIn delay={0}><SocialPanel social={social} audioRef={audioRef}/></SlideIn>}
      <SlideIn delay={0}><OSINTPanel osint={osint} audioRef={audioRef}/></SlideIn>
      <SlideIn delay={80}><SourceGroup r={r} audioRef={audioRef}/></SlideIn>
      <SlideIn delay={160}><ContentGroup r={r} audioRef={audioRef}/></SlideIn>
      <SlideIn delay={240}><ContextGroup r={r} audioRef={audioRef}/></SlideIn>
      <SlideIn delay={320}><ResearchSection r={r} audioRef={audioRef}/></SlideIn>
    </div>}
  </div>;
}

// ── REPUTATION DB ─────────────────────────────────────────────────────────────
function RepoDB({audioRef}){
  const [idx,setIdx]=useState(null),[sel,setSel]=useState(null),[hist,setHist]=useState([]);
  useEffect(()=>{loadIdx().then(setIdx);},[]);
  async function select(d){audioRef.current.beep();setSel(d);setHist(await loadHist(d));}
  if(!idx)return <ACard><span style={{fontFamily:M,fontSize:9,color:P.dim}}>LOADING...</span></ACard>;
  const domains=Object.keys(idx).sort((a,b)=>(idx[a].s||0)-(idx[b].s||0));
  return <ACard title="REPUTATION DATABASE" color={P.purple}>
    <div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:10,lineHeight:1.8}}>Agent endpoint: <span style={{color:P.teal}}>window.__TRUTHILIZER_INDEX__</span><br/>Schema v2 · {domains.length} domains · bitmask flags · confidence intervals</div>
    {domains.length===0&&<div style={{fontFamily:M,fontSize:9,color:P.dim}}>No entries yet.</div>}
    {domains.map(d=>{const rec=idx[d],c=scoreColor(rec.s),recFlags=flagsToStrings(rec.f||0);return <div key={d} onClick={()=>select(d)} style={{display:"flex",alignItems:"center",gap:10,background:sel===d?P.alt:P.bg,borderRadius:3,padding:"8px 10px",marginBottom:5,cursor:"pointer",borderLeft:`2px solid ${c}`}}>
      <div style={{flex:1}}><div style={{fontFamily:M,fontSize:9,color:P.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d}</div>{recFlags.length>0&&<div style={{marginTop:3}}>{recFlags.slice(0,2).map((f,i)=><Badge key={i} text={f} color={P.red}/>)}</div>}</div>
      {rec.ci&&<span style={{fontFamily:M,fontSize:8,color:P.dim}}>{rec.ci.lo}-{rec.ci.hi}</span>}
      <Badge text={POL_LABELS[rec.p||3]||"C"} color={P.amber}/>
      {rec.os!=null&&<span style={{fontFamily:M,fontSize:8,color:scoreColor(rec.os)}}>{"O:"+rec.os}</span>}
      <span style={{fontFamily:M,fontSize:11,color:c,minWidth:28,textAlign:"right"}}>{rec.s}</span>
    </div>;})}
    {sel&&hist.length>0&&<div style={{marginTop:12,paddingTop:10}}>
      <NeonDivider color={P.purple} mt={0} mb={10}/>
      <div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:8}}>HISTORY: {sel}</div>
      {hist.map((h,i)=>{const c=scoreColor(h.s),hFlags=flagsToStrings(h.f||0);return <NeonCell key={i} color={c} pad="8px 10px" style={{marginBottom:5}}>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
          <span style={{fontFamily:M,fontSize:8,color:P.dim}}>{daysToDate(h.t)}</span>
          {h.wa!=null&&<span style={{fontFamily:M,fontSize:8,color:P.dim}}>{"age:"+(h.wa/365).toFixed(1)+"y"}</span>}
          {h.gd!=null&&<span style={{fontFamily:M,fontSize:8,color:P.teal}}>{"gdelt:"+h.gd}</span>}
          {h.ci&&<span style={{fontFamily:M,fontSize:8,color:P.dim}}>{h.ci.lo+"-"+h.ci.hi}</span>}
          <span style={{fontFamily:M,fontSize:10,color:c,marginLeft:"auto"}}>{h.s}</span>
          {h.os!=null&&<span style={{fontFamily:M,fontSize:9,color:scoreColor(h.os)}}>{"os:"+h.os}</span>}
        </div>
        <div style={{display:"flex",flexWrap:"wrap",gap:4}}>{hFlags.map((f,j)=><Badge key={j} text={f} color={P.red}/>)}{h.q!=null&&<Badge text={"FCK:"+h.q} color={scoreColor(h.q)}/>}{h.h!=null&&<Badge text={"HL:"+h.h} color={scoreColor(h.h)}/>}{h.ow&&<Badge text={h.ow} color={P.amber}/>}</div>
        {h.cs?.length>0&&<div style={{marginTop:6}}><div style={{fontFamily:M,fontSize:7,color:P.dim,marginBottom:3}}>CLAIM SCORES</div><div style={{display:"flex",gap:4}}>{h.cs.map((s,j)=><span key={j} style={{fontFamily:M,fontSize:9,color:scoreColor(s)}}>{s}</span>)}</div></div>}
        {h.sum&&<p style={{fontFamily:M,fontSize:8,color:P.dim,margin:"5px 0 0",lineHeight:1.6}}>{h.sum}</p>}
      </NeonCell>;})}
    </div>}
  </ACard>;
}

// ── API ───────────────────────────────────────────────────────────────────────
const SYS_SCHEMA='{"overallScore":<0-100>,"summary":"<2-3 sentences>","claims":[{"claim":"<verifiable claim>","score":<0-100>,"verdict":"<1 sentence>"}],"researchQueries":[{"query":"<plain english>","type":"SCHOLAR|PUBMED|NEWS|WIKI|GENERAL","source":"<n>","url":"<encoded url>"}],"consensus":{"highCred":<int>,"lowCred":<int>,"echoOnly":<0|1>,"overallPattern":"strong|mixed|fringe","summary":"<1-2 sentences>"},"headline":{"score":<0-100>,"match":"ACCURATE|MISLEADING|CLICKBAIT|UNVERIFIABLE","analysis":"<1-2 sentences>","flags":[]},"rhetoric":[{"type":"<fallacy>","severity":"high|medium|low","excerpt":"<quote>","explanation":"<1 sentence>"}],"missingContext":[{"type":"MISSING STAT SOURCE|MISSING SAMPLE SIZE|MISSING TIMEFRAME|SELECTIVE QUOTING|OTHER","description":"<1 sentence>"}],"temporal":{"published":"<date>","circulationPattern":"<desc>","riskLevel":"high|medium|low","summary":"<1-2 sentences>","corrections":[]},"ownership":{"chain":[{"name":"<entity>","note":"<brief>"}],"conflictOfInterest":"<desc or null>","summary":"<1 sentence>"},"similarArticles":[{"outlet":"<n>","headline":"<h>","credibility":"HIGH|MED|LOW","framingNote":"<diff>"}],"criteria":{"source":{"score":<int>,"summary":"<1 sentence>","flags":[]},"funding":{"score":<int>,"summary":"<1 sentence>","flags":[]},"author":{"score":<int>,"summary":"<1 sentence>","flags":[]},"authorPay":{"score":<int>,"summary":"<1 sentence>","flags":[]},"copyPaste":{"score":<int>,"summary":"<1 sentence>","flags":[]},"study":{"score":<int>,"summary":"<1 sentence>","flags":[]},"academic":{"score":<int>,"summary":"<1 sentence>","flags":[]},"factCheck":{"score":<int>,"summary":"<1 sentence>","flags":[]}},"interestGroups":{"labels":["Corp Media","Govt","NGO","Partisan","Academic","Foreign","Industry","Independent"],"values":[0,0,0,0,0,0,0,0]},"politicalLeanings":{"labels":["Far Left","Left","Ctr-Left","Center","Ctr-Right","Right","Far Right","Natl"],"values":[0,0,0,0,0,0,0,0]}}';
const SYSTEM_PROMPT="You are a rigorous media literacy AI. Search the web to analyze this URL, then return ONLY valid JSON matching this schema — no markdown, no prose, no explanation:\n"+SYS_SCHEMA;
const AI_MSGS=["EXTRACTING CLAIMS...","TRACING OWNERSHIP...","SCANNING RHETORIC...","MAPPING CONSENSUS...","FOLLOWING MONEY...","CHECKING LOGIC...","MINING CONTEXT...","TEMPORAL ANALYSIS...","COMPUTING TRUTH MATRIX..."];

async function callAPISingleShot(userMsg){
  const body={model:"claude-sonnet-4-20250514",max_tokens:4000,system:SYSTEM_PROMPT,tools:[{type:"web_search_20250305",name:"web_search"}],messages:[{role:"user",content:userMsg}]};
  const res=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  if(!res.ok){const t=await res.text().catch(()=>"");throw new Error("HTTP "+res.status+(t?" — "+t.slice(0,120):""));}
  const data=await res.json();
  if(data.error)throw new Error(data.error.message||JSON.stringify(data.error));
  const text=(data.content||[]).filter(b=>b.type==="text").map(b=>b.text).join("");
  const clean=text.replace(/```json\n?|```\n?/g,"").trim();
  const match=clean.match(/\{[\s\S]*\}/);if(!match)throw new Error("No JSON in response");
  return JSON.parse(match[0]);
}

// ── APP ───────────────────────────────────────────────────────────────────────
export default function App(){
  const [url,setUrl]=useState("");
  const [busy,setBusy]=useState(false);
  const [results,setResults]=useState(null);
  const [osint,setOsint]=useState(null);
  const [ci,setCi]=useState(null);
  const [social,setSocial]=useState(null);
  const [isSocial,setIsSocial]=useState(false);
  const [fromCache,setFromCache]=useState(false);
  const [cachedAt,setCachedAt]=useState(null);
  const [msg,setMsg]=useState("");
  const [err,setErr]=useState("");
  const [tab,setTab]=useState("scan");
  const [repoBust,setRepoBust]=useState(0);
  const [flash,setFlash]=useState(false);
  const [repoCount,setRepoCount]=useState(0);
  const [clock,setClock]=useState("");
  const ivRef=useRef(null),audioRef=useAudio(),scoreRef=useRef(null),busyRef=useRef(false);

  useEffect(()=>{scoreRef.current=results?results.overallScore:null;},[results]);
  useEffect(()=>{return()=>clearInterval(ivRef.current);},[]);
  useEffect(()=>{loadIdx().then(i=>setRepoCount(Object.keys(i).length));},[repoBust]);
  useEffect(()=>{const iv=setInterval(()=>setClock(new Date().toTimeString().slice(0,8)),1000);setClock(new Date().toTimeString().slice(0,8));return()=>clearInterval(iv);},[]);

  const runAnalysis=useCallback(async(urlStr,skipCache)=>{
    if(!urlStr.trim()||busy||busyRef.current)return;
    if(!isValidUrl(urlStr.trim())){setErr("Invalid URL. Must start with http:// or https://");return;}
    busyRef.current=true;
    audioRef.current.beep();
    setBusy(true);setResults(null);setOsint(null);setCi(null);setSocial(null);setErr("");setFromCache(false);
    const urlIsSocial=isSocialUrl(urlStr.trim());setIsSocial(urlIsSocial);
    if(!skipCache){
      const cached=await getCached(urlStr.trim());
      if(cached?.results){
        setResults(cached.results);setOsint(cached.osint||null);setCi(cached.ci||null);setSocial(cached.social||null);
        setFromCache(true);setCachedAt(cached.cachedAt);
        audioRef.current.chime(cached.results.overallScore);
        setFlash(true);setTimeout(()=>setFlash(false),400);
        busyRef.current=false;setBusy(false);return;
      }
    }
    setMsg(AI_MSGS[0]);
    try{
      const [osintData,socialData]=await Promise.all([
        runOSINT(urlStr.trim()),
        urlIsSocial?analyzeSocialPost(urlStr.trim()):Promise.resolve(null)
      ]);
      setOsint(osintData);if(socialData)setSocial(socialData);
      let mi=0;ivRef.current=setInterval(()=>{mi=(mi+1)%AI_MSGS.length;setMsg(AI_MSGS[mi]);},1900);
      const ctx=["OSINT PRE-FLIGHT:",
        "- Domain age: "+(osintData.whois?osintData.whois.ageYears+" years":"unknown"),
        "- GDELT articles: "+(osintData.gdelt?osintData.gdelt.count:"no data"),
        "- Bad actor list: "+(osintData.openSources?.flagged?"FLAGGED":"clear"),
        "- Wayback: "+(osintData.wayback?.available?"First seen "+osintData.wayback.firstSeen:"No archive"),
        "- Fact checks found: "+(osintData.factChecks?osintData.factChecks.length:0),
        "- Retracted citations: "+(osintData.scholar?.some(p=>p.retracted)?"YES - CRITICAL":"none")
      ].join("\n");
      const socialCtx=urlIsSocial&&socialData
        ?"\nSOCIAL POST:\n- Type: "+(socialData.postType||"Unknown")+"\n- Opinion: "+(socialData.isOpinion?"YES":"NO")+"\n- Author cred: "+(socialData.authorCredibility||"?")+"/100\n- Claims: "+(socialData.claimsMade||[]).join("; ")
        :"";
      const uMsg="Analyze credibility of: "+urlStr.trim()+"\n"+ctx+socialCtx+"\nReturn ONLY the JSON object."+(urlIsSocial?" Note: social media post — distinguish opinion from fact clearly.":"");
      const parsed=await callAPISingleShot(uMsg);
      const ciData=computeConfidenceInterval(parsed.overallScore,osintData);
      clearInterval(ivRef.current);
      setResults(parsed);setCi(ciData);
      audioRef.current.chime(parsed.overallScore);
      setFlash(true);setTimeout(()=>setFlash(false),400);
      await setCached(urlStr.trim(),{results:parsed,osint:osintData,ci:ciData,social:socialData});
      await saveRep(parsed,urlStr.trim(),osintData,ciData);
      setRepoBust(k=>k+1);
    }catch(e){
      clearInterval(ivRef.current);setErr(classifyError(e));
    }finally{
      busyRef.current=false;setBusy(false);
    }
  },[busy]);

  const analyze=useCallback(()=>runAnalysis(url,false),[url,runAnalysis]);
  const reanalyze=useCallback(()=>runAnalysis(url,true),[url,runAnalysis]);
  function reset(){audioRef.current.beep();setResults(null);setOsint(null);setCi(null);setSocial(null);setIsSocial(false);setUrl("");setErr("");setFromCache(false);}
  function onKey(e){if(e.key==="Enter")analyze();}

  return <div style={{background:P.bg,minHeight:"100vh",paddingBottom:32,fontFamily:M,position:"relative",zIndex:1}}>
    <style>{`@import url('${GFONT}');*{box-sizing:border-box}input::placeholder{color:${P.dim}}input:focus{outline:none;}::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:${P.bg}}::-webkit-scrollbar-thumb{background:${P.border};border-radius:2px}@keyframes vu{from{transform:scaleY(.3)}to{transform:scaleY(1)}}@keyframes blink{0%,100%{opacity:1}50%{opacity:.15}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}`}</style>

    <AmbientGlow score={results?results.overallScore:null}/>
    <FlashOverlay show={flash} color={results?scoreColor(results.overallScore):P.teal}/>
    <Eyes scoreRef={scoreRef}/>

    <LiveBorder color={P.teal} style={{background:P.panel,borderRadius:0}}>
      <div style={{padding:"10px 18px",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <div>
          <div style={{fontFamily:M,fontSize:20,color:P.teal,letterSpacing:5}}>TRUTHILIZER</div>
          <div style={{fontFamily:M,fontSize:8,color:P.dim,letterSpacing:2,marginTop:2}}>SIGNAL ANALYSIS TERMINAL v12.0</div>
        </div>
        <div style={{textAlign:"right"}}>
          <div style={{fontFamily:M,fontSize:11,color:P.amber}}>{clock}</div>
          <div style={{fontFamily:M,fontSize:8,color:P.dim,marginTop:2}}>
            <span style={{animation:"pulse 2s infinite",color:results?P.green:busy?P.amber:P.dim}}>●</span>
            {" "}{results?"SCAN COMPLETE":busy?"SCANNING":"STANDBY"}
          </div>
        </div>
      </div>
    </LiveBorder>
    <NeonLine color={P.teal}/>

    <div style={{display:"flex"}}>
      {[{id:"scan",l:"SCANNER",c:P.teal},{id:"repo",l:"REPUTATION DB"+(repoCount>0?" ["+repoCount+"]":""),c:P.purple}].map(t=>{
        const active=tab===t.id;
        return <LiveBorder key={t.id} color={active?t.c:P.border} style={{flex:1,background:active?P.alt:P.bg,borderRadius:0}}>
          <button onClick={()=>{setTab(t.id);audioRef.current.beep();}} style={{width:"100%",fontFamily:M,fontSize:9,padding:"10px",background:"transparent",color:active?t.c:P.dim,border:"none",cursor:"pointer",letterSpacing:2}}>{t.l}</button>
        </LiveBorder>;
      })}
    </div>
    <NeonLine color={tab==="scan"?P.teal:P.purple}/>

    <div style={{padding:"14px 14px 0"}}>
      {tab==="scan"&&<div>
        <MusicPanel audioRef={audioRef} score={results?results.overallScore:null}/>
        <ACard title="TARGET URL" color={busy?P.amber:results?scoreColor(results.overallScore):P.teal}>
          <div style={{display:"flex",gap:8}}>
            <input value={url} onChange={e=>{setUrl(e.target.value);setErr("");}} onKeyDown={onKey} placeholder="PASTE URL TO ANALYZE..." style={{flex:1,fontFamily:M,fontSize:10,background:P.bg,color:P.teal,border:"none",padding:"10px 12px",borderRadius:3}}/>
            <LiveBorder color={busy?P.amber:P.teal} style={{borderRadius:3}}>
              <button onClick={analyze} disabled={busy||!url.trim()} style={{fontFamily:M,fontSize:9,background:busy?P.alt:P.tealD,color:busy?P.dim:P.teal,border:"none",padding:"10px 18px",cursor:busy?"default":"pointer",borderRadius:3,whiteSpace:"nowrap",letterSpacing:1}}>
                <ScrambleText text={busy?"SCANNING...":"ANALYZE ▶"} active={busy}/>
              </button>
            </LiveBorder>
          </div>
          {busy&&<div style={{fontFamily:M,fontSize:9,color:P.amber,marginTop:8,animation:"blink 1s step-end infinite"}}>{msg}</div>}
          {!busy&&isSocial&&!results&&<div style={{fontFamily:M,fontSize:8,color:P.pink,marginTop:6}}>◈ Social post detected — image, claim &amp; account analysis will run in parallel</div>}
          {err&&<div style={{fontFamily:M,fontSize:9,color:P.red,marginTop:8}}>⚠ {err}</div>}
        </ACard>

        {results&&<div>
          <Results r={results} osint={osint} ci={ci} social={social} audioRef={audioRef} fromCache={fromCache} cachedAt={cachedAt} onReanalyze={reanalyze}/>
          <div style={{marginTop:16,textAlign:"center"}}>
            <LiveBorder color={P.dim} style={{display:"inline-block",borderRadius:3}}>
              <button onClick={reset} style={{fontFamily:M,fontSize:9,background:P.panel,color:P.dim,border:"none",padding:"9px 22px",cursor:"pointer",borderRadius:3,letterSpacing:1}}>◀ NEW SCAN</button>
            </LiveBorder>
          </div>
        </div>}
      </div>}
      {tab==="repo"&&<RepoDB key={repoBust} audioRef={audioRef}/>}
    </div>

    <div style={{marginTop:24,padding:"14px",borderTop:`1px solid ${P.border}`,textAlign:"center"}}>
      <div style={{fontFamily:M,fontSize:8,color:P.dim,marginBottom:6,letterSpacing:1}}>DONATE TO THE DEV</div>
      <div style={{fontFamily:M,fontSize:7,color:P.teal,marginBottom:4}}>BTC: 38ioq7FqjnPe7k8m92jN3D5DTusyKhpYmj</div>
      <div style={{fontFamily:M,fontSize:7,color:P.purple}}>ETH: 0xbAF95cA8Ff801CCBa8F91152d7Bd87CEFf6a7661</div>
    </div>
  </div>;
}