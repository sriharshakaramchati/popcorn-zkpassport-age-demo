import test from 'node:test';
import assert from 'node:assert/strict';
import {AgeFlow} from '../src/flow.mjs';
import {bindingContext,signCredential,verifyCredential} from '../src/binding.mjs';
const key='x'.repeat(32),now=1800000000000;
function fixture(mode='popcorn-connected',verifyProof=async()=>({verified:true})){
 const flow=new AgeFlow({key,verifyProof,now:()=>now});
 const record=flow.create({owner:'owner',session:{id:'session-1',expiresAt:new Date(now+600000).toISOString()},mode});
 flow.setQuery(record,{age:{gte:18},bind:{custom_data:record.binding}});
 const payload={verified:true,result:{age:{gte:{result:true,expected:18}},bind:{custom_data:record.binding}},proofs:[{}]};
 return {flow,record,payload};
}
test('connected proof success stays labelled non-attested and redeems once',async()=>{
 const {flow,record,payload}=fixture();assert.equal(await flow.accept(record,payload),true);
 assert.equal(record.verificationUrl,undefined);assert.equal(flow.redeem(record.id,'owner').claims.mode,'popcorn-connected');
 assert.throws(()=>flow.redeem(record.id,'owner'));assert.equal(flow.owned(record.id,'wrong'),null);
});
test('attested mode fails closed without verifier',async()=>{const {flow,record,payload}=fixture('popcorn-attested');assert.equal(await flow.accept(record,payload),false);assert.equal(record.status,'failed')});
test('server verification failure cannot redeem',async()=>{const {flow,record,payload}=fixture('popcorn-connected',async()=>({verified:false}));assert.equal(await flow.accept(record,payload),false);assert.throws(()=>flow.redeem(record.id,'owner'))});
test('binding mismatch fails',async()=>{const {flow,record,payload}=fixture();payload.result.bind.custom_data='wrong';assert.equal(await flow.accept(record,payload),false)});
test('mode/session/nonce mismatch and expiration invalidate credential',()=>{
 const nonce='a'.repeat(64),claims={v:1,aud:'popcorn-zkpassport-age-demo',ageOver18:true,sessionId:'s',nonce,iat:now,exp:now+1000,mode:'popcorn-connected'},token=signCredential(claims,key);
 assert.ok(verifyCredential(token,key,'s',nonce,now,'popcorn-connected'));
 assert.equal(verifyCredential(token,key,'s',nonce,now,'popcorn-attested'),null);
 assert.equal(verifyCredential(token,key,'other',nonce,now,'popcorn-connected'),null);
 assert.equal(verifyCredential(token,key,'s',nonce,now+1000,'popcorn-connected'),null);
 assert.notEqual(bindingContext('s',nonce),bindingContext('other',nonce));
});
