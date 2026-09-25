'use strict';
const fs=require('node:fs'),path=require('node:path'),readline=require('node:readline'),{spawn}=require('node:child_process');
const directory=__dirname,root=path.resolve(directory,'../..');
const children=[],outputs=[];
fs.writeFileSync(path.join(directory,'event-capture.json'),JSON.stringify({pid:process.pid,started_at:new Date().toISOString(),scope:'Live JSON timing events, started before the measured read window; follows file rotation and the write-case node restart.'},null,2)+'\n');
for(const side of ['a','b']){
 const output=fs.createWriteStream(path.join(directory,`events-${side}.jsonl`),{flags:'a'});outputs.push(output);
 const child=spawn('tail',['-n','0','-F','--sleep-interval=0.1','--max-unchanged-stats=1',path.join(root,`localnet/logs-e2e-local-feature-1-${side}/dev/reth.log`)],{stdio:['ignore','pipe','ignore']});children.push(child);
 readline.createInterface({input:child.stdout}).on('line',line=>{
  if(!/Bench transaction attempt|New payload job created|Built payload|subscriber went away|"message":"Executed block"/.test(line))return;
  try{JSON.parse(line);output.write(line+'\n');}catch{}
 });
}
function finish(){children.forEach(c=>c.kill());outputs.forEach(o=>o.end());clearInterval(timer);}
const timer=setInterval(()=>{if(fs.existsSync(path.join(directory,'capture.stop')))finish();},1000);
process.on('SIGTERM',finish);process.on('SIGINT',finish);
