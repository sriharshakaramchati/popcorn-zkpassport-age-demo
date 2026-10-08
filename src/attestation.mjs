import {readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {verifyProof,fetchGoogleKeys} from './gcp-proof.mjs';
const run=promisify(execFile);
export async function verifySessionAttestation({session,nonce,origin,policyPath=process.env.ATTESTATION_POLICY_PATH}){
 if(!policyPath)throw Error('Approved attestation policy missing');
 const policy=JSON.parse(await readFile(policyPath,'utf8'));
 if(!policy.service_account)throw Error('Approved service account missing');
 const gateway=new URL(policy.audience);
 if(gateway.protocol!=='https:'||gateway.username||gateway.password||gateway.search||gateway.hash||gateway.pathname!=='/')throw Error('Invalid approved gateway');
 if(new URL(session.liveViewUrl).origin!==gateway.origin)throw Error('Allocated gateway not approved');
 const proofUrl=new URL('/proof/'+encodeURIComponent(session.id),gateway);proofUrl.searchParams.set('nonce',nonce);
 const response=await fetch(proofUrl,{redirect:'error',signal:AbortSignal.timeout(20000)});
 if(!response.ok)throw Error('Attestation unavailable');
 const reader=response.body.getReader(),chunks=[];let size=0;
 try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>262144)throw Error('Attestation too large');chunks.push(value)}}finally{await reader.cancel()}
 const proof=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 const result=verifyProof(proof,nonce,policy,await fetchGoogleKeys());
 const publicKey=fileURLToPath(new URL('./cosign.pub',import.meta.url));
 for(const image of [proof.workload.image_digest,proof.verifier.image_digest]){
  await run(process.env.COSIGN_BIN||'cosign',['verify','--key',publicKey,image],{timeout:20000,maxBuffer:262144});
 }
 if(result.platform_and_image_assertion_verified!==true)throw Error('Invalid verification result');
 const claims=JSON.parse(Buffer.from(proof.attestation.token.split('.')[1],'base64url').toString());
 return {verified:true,sessionId:session.id,nonce,expiresAt:new Date(Math.min(claims.exp*1000,Date.now()+policy.max_age_seconds*1000)).toISOString(),verificationUrl:origin+'/attestation/'+encodeURIComponent(session.id),scope:result.scope};
}
