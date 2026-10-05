import { randomUUID } from 'node:crypto';
import { bindingContext, hexNonce, signCredential, verifyCredential, requireExactProofQuery } from './binding.mjs';
export const SCOPE='popcorn-age-demo-v1';
export class AgeFlow {
 constructor({key,verifyProof,verifyAttestation,now=()=>Date.now()}){this.key=key;this.verifyProof=verifyProof;this.verifyAttestation=verifyAttestation;this.now=now;this.records=new Map()}
 create({owner,session,mode}){
  if(!['passport-only','popcorn-attested'].includes(mode))throw Error('Unsupported flow mode');
  const nonce=hexNonce(),id=randomUUID(),created=this.now();
  const record={id,owner,session,mode,nonce,binding:bindingContext(session.id,nonce),created,expires:Math.min(created+600000,Date.parse(session.expiresAt)),status:'pending',consumed:false};
  if(!Number.isFinite(record.expires)||record.expires<=created)throw Error('Session expired');
  this.records.set(id,record);return record;
 }
 setQuery(record,query){requireExactProofQuery(query,record.binding);record.query=structuredClone(query)}
 owned(id,owner){const r=this.records.get(id);if(!r||r.owner!==owner)return null;if(this.now()>=r.expires&&r.status!=='redeemed'){r.status='expired';delete r.credential}return r}
 async accept(record,{verified,result,proofs}){
  if(record.status!=='pending'||record.processing||this.now()>=record.expires)return false;
  record.processing=true;
  try{
   requireExactProofQuery(record.query,record.binding);
   if(verified!==true||result?.age?.gte?.result!==true||result?.age?.gte?.expected!==18||result?.bind?.custom_data!==record.binding||!Array.isArray(proofs)||proofs.length===0)throw Error('Age or binding assertion failed');
   const verification=await this.verifyProof({proofs,originalQuery:record.query,queryResult:result,scope:SCOPE,devMode:false,validity:600});
   if(verification?.verified!==true)throw Error('Server proof verification failed');
   let attestation;
   if(record.mode==='popcorn-attested'){
    if(!this.verifyAttestation)throw Error('Attestation verifier unavailable');
    attestation=await this.verifyAttestation(record);
    if(attestation?.verified!==true||attestation.sessionId!==record.session.id||attestation.nonce!==record.nonce||!Number.isFinite(Date.parse(attestation.expiresAt))||Date.parse(attestation.expiresAt)<=this.now()||!attestation.verificationUrl||new URL(attestation.verificationUrl).protocol!=='https:')throw Error('Attestation did not bind this session');
   }
   if(record.status!=='pending'||this.now()>=record.expires)throw Error('Flow expired while verifying');
   const now=this.now(),exp=Math.min(now+300000,record.expires,attestation?Date.parse(attestation.expiresAt):Infinity);
   record.credential=signCredential({v:1,aud:'popcorn-zkpassport-age-demo',ageOver18:true,sessionId:record.session.id,nonce:record.nonce,iat:now,exp,mode:record.mode},this.key);
   record.credentialExpires=exp;record.verificationUrl=attestation?.verificationUrl;record.status='ready';return true;
  }catch{record.status='failed';record.error='Verification failed. Start a new request.';return false}finally{record.processing=false}
 }
 redeem(id,owner){
  const record=this.owned(id,owner);if(!record||record.status!=='ready'||record.consumed)throw Error('No redeemable credential');
  const claims=verifyCredential(record.credential,this.key,record.session.id,record.nonce,this.now(),record.mode);
  if(!claims){record.status='expired';delete record.credential;throw Error('Credential expired or invalid')}
  record.consumed=true;record.status='redeemed';delete record.credential;return {record,claims};
 }
 sweep(){const expired=[];for(const [id,r] of this.records){if(this.now()>=r.expires){expired.push(r);this.records.delete(id)}}return expired}
}
