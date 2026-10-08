import {build} from 'esbuild';
const stub={name:'stub-bb',setup(b){
 b.onResolve({filter:/^@aztec\/bb\.js(-v4)?(\/.*)?$/},a=>({path:a.path,namespace:'stub'}));
 b.onLoad({filter:/.*/,namespace:'stub'},()=>({contents:'module.exports=new Proxy({},{get:(_,k)=>k==="__esModule"?false:class Unsupported{constructor(){throw new Error("Server-side verification only")}}})',loader:'js'}));
}};
await build({entryPoints:['src/client/entry.mjs'],bundle:true,format:'iife',platform:'browser',minify:true,outfile:process.argv[2]||'src/client/zk-browser.js',plugins:[stub],define:{'process.env.NODE_ENV':'"production"'},logLevel:'warning'});
