import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, writeFile, readFile, mkdtemp, statfs } from 'node:fs/promises';
import { resolve, join, delimiter } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { X509Certificate } from 'node:crypto';
import { createServer as httpsServer } from 'node:https';
import pg from 'pg';

export async function freePort(){const socket=createServer();await new Promise((done)=>socket.listen(0,'127.0.0.1',done));const port=socket.address().port;await new Promise((done)=>socket.close(done));return port;}
export async function eventually(work,timeout=20_000){const end=Date.now()+timeout;let error;while(Date.now()<end){try{const result=await work();if(result)return result;}catch(failure){error=failure;}await new Promise((done)=>setTimeout(done,100));}throw error??new Error('SERVICE_READINESS_TIMEOUT');}
export function child(command,args,options={}){const process=spawn(command,args,{windowsHide:true,stdio:['pipe','pipe','pipe'],...options});let output='';process.stdout.on('data',(chunk)=>{output=(output+chunk).slice(-64*1024);});process.stderr.on('data',(chunk)=>{output=(output+chunk).slice(-64*1024);});const done=new Promise((resolve,reject)=>{process.once('error',reject);process.once('exit',(code)=>resolve(code));});return{process,done,output:()=>output,async stop(){if(process.exitCode!==null)return;process.kill('SIGTERM');await Promise.race([done,new Promise((done)=>setTimeout(done,5000))]);if(process.exitCode===null){process.kill('SIGKILL');await done;}}};}
async function command(path,args,options={}){const item=child(path,args,options);if(await item.done!==0)throw new Error(`LAB_COMMAND_FAILED:${item.output().replace(/password[^\s]*/gi,'<redacted>').slice(-2000)}`);}

/** Owns fresh loopback services and their data only. No Docker reset or existing database mutation. */
export async function startNativeScaleLab(){
  if(process.platform!=='win32')throw new Error('NATIVE_LAB_REQUIRES_WINDOWS_USE_SERVICE_ENV_ON_CI');
  const root=resolve('.routecairn-scale-lab');await mkdir(join(root,'runs'),{recursive:true});const capacity=await statfs(root);if(capacity.bavail*capacity.bsize<capacity.blocks*capacity.bsize*0.01+256*1024*1024)throw new Error('LAB_DISK_SPACE_REQUIRES_MINIO_ONE_PERCENT_RESERVE_PLUS_256_MIB');const directory=await mkdtemp(join(root,'runs','native-'));
  const binaries=join(root,'tools'),pgBin=join(binaries,'postgresql','pgsql','bin'),minio=join(binaries,'minio.exe'),otel=join(binaries,'otelcol-contrib.exe');
  const pgPort=await freePort(),s3Port=await freePort(),consolePort=await freePort(),kmsPort=await freePort(),otelPort=await freePort();
  const password=randomBytes(24).toString('hex'),access=randomBytes(12).toString('hex'),secret=randomBytes(24).toString('hex');
  const pwfile=join(directory,'postgres-password');await writeFile(pwfile,password,{mode:0o600});
  const data=join(directory,'postgres');await command(join(pgBin,'initdb.exe'),['-D',data,'-U','routecairn','--pwfile',pwfile,'--auth=scram-sha-256','--encoding=UTF8','--locale=C']);
  await writeFile(join(data,'postgresql.conf'),`listen_addresses='127.0.0.1'\nport=${pgPort}\nmax_connections=80\nfsync=on\n`);
  const started=[];let postgresStarted=false;
  const close=async()=>{const stopped=await Promise.allSettled(started.map((item)=>item.stop()));if(postgresStarted){await command(join(pgBin,'pg_ctl.exe'),['-D',data,'-m','fast','-w','stop']);postgresStarted=false;}if(stopped.some((item)=>item.status==='rejected'))throw new Error('LAB_PROCESS_CLEANUP_FAILED');};
  try{
    await command(join(pgBin,'pg_ctl.exe'),['-D',data,'-l',join(directory,'postgres.log'),'-w','start']);postgresStarted=true;
    const url=`postgresql://routecairn:${password}@127.0.0.1:${pgPort}/postgres`,pool=new pg.Pool({connectionString:url});await pool.query('CREATE DATABASE routecairn');await pool.end();
    const environment={...process.env,ROUTECAIRN_CONTROL_PLANE_MODE:'distributed',ROUTECAIRN_DATABASE_URL:url.replace(/\/postgres$/,'/routecairn'),ROUTECAIRN_EVIDENCE_S3_BUCKET:'routecairn-scale-lab',ROUTECAIRN_EVIDENCE_S3_ENDPOINT:`http://127.0.0.1:${s3Port}`,ROUTECAIRN_EVIDENCE_S3_PATH_STYLE:'true',ROUTECAIRN_EVIDENCE_S3_ENCRYPTION:'provider',AWS_ACCESS_KEY_ID:access,AWS_SECRET_ACCESS_KEY:secret,AWS_REGION:'us-east-1',AWS_EC2_METADATA_DISABLED:'true',ROUTECAIRN_JOB_CLAIM_WAIT_MS:'0',ROUTECAIRN_JOB_LEASE_MS:'15000',ROUTECAIRN_LEADER_LEASE_MS:'5000',ROUTECAIRN_LOG_LEVEL:'error',OTEL_EXPORTER_OTLP_ENDPOINT:`http://127.0.0.1:${otelPort}`,ROUTECAIRN_LAB_KMS_ENDPOINT:`http://127.0.0.1:${kmsPort}`};
    started.push(child(minio,['server',join(directory,'objects'),'--address',`127.0.0.1:${s3Port}`,'--console-address',`127.0.0.1:${consolePort}`],{env:{...environment,MINIO_ROOT_USER:access,MINIO_ROOT_PASSWORD:secret}}));
    await eventually(async()=> (await fetch(`${environment.ROUTECAIRN_EVIDENCE_S3_ENDPOINT}/minio/health/ready`)).ok);
    await command(process.execPath,['dist/cli/index.js','initialize-evidence-storage'],{env:environment});
    await command(process.execPath,['dist/cli/index.js','initialize-evidence-storage'],{env:environment});
    started.push(child(process.env.ROUTECAIRN_LAB_PYTHON??'python',['tests/helpers/moto-kms-server.py',String(kmsPort)],{env:{...environment,PYTHONPATH:[join(root,'python'),process.env.PYTHONPATH].filter(Boolean).join(delimiter)}}));
    await eventually(async()=> (await fetch(environment.ROUTECAIRN_LAB_KMS_ENDPOINT)).ok);
    const telemetryPath=join(directory,'telemetry.jsonl'),otelConfig=join(directory,'otel.json');
    await writeFile(otelConfig,JSON.stringify({receivers:{otlp:{protocols:{http:{endpoint:`127.0.0.1:${otelPort}`}}}},exporters:{file:{path:telemetryPath}},service:{pipelines:{traces:{receivers:['otlp'],exporters:['file']},metrics:{receivers:['otlp'],exporters:['file']}}}}));
    started.push(child(otel,['--config',otelConfig]));await eventually(async()=>{await fetch(`${environment.OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});return true;});
    const provenance=[];for(const path of [join(pgBin,'postgres.exe'),minio,otel])provenance.push({name:path.split(/[\\/]/).pop(),sha256:createHash('sha256').update(await readFile(path)).digest('hex')});
    return{environment,directory,telemetryPath,provenance,close,restartDatabase:async()=>{
      await command(join(pgBin,'pg_ctl.exe'),['-D',data,'-m','fast','-w','stop']);
      await command(join(pgBin,'pg_ctl.exe'),['-D',data,'-l',join(directory,'postgres.log'),'-w','start']);
    }};
  }catch(error){await close();throw error;}
}

export async function startFleetReplica(environment,transport={}){const port=await freePort();const args=['dist/cli/index.js','fleet','--port',String(port),...(transport.certFile?['--tls-cert',transport.certFile,'--tls-key',transport.keyFile,'--tls-ca',transport.caFile]:[])];const item=child(process.execPath,args,{env:environment});const url=`${transport.certFile?'https':'http'}://127.0.0.1:${port}`;try{await eventually(async()=>{if(item.process.exitCode!==null)throw new Error(`FLEET_START_FAILED:${item.output()}`);return (await fetch(`${url}/readyz`,transport.dispatcher?{dispatcher:transport.dispatcher}:{})).ok;});return{...item,url};}catch(error){await item.stop();throw error;}}

export async function startIdentityLab(directory,jwks){
  const openssl=process.env.ROUTECAIRN_LAB_OPENSSL??'C:/Program Files/Git/usr/bin/openssl.exe';
  directory=join(directory,'identity');await mkdir(directory,{recursive:true});const caFile=join(directory,'ca.pem'),caKey=join(directory,'ca.key');
  await command(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-keyout',caKey,'-out',caFile,'-days','2','-subj','/CN=RouteCairn owned identity lab','-addext','basicConstraints=critical,CA:TRUE']);
  const certificates={};
  for(const name of ['server','worker-a','worker-b']){
    const keyFile=join(directory,`${name}.key`),certFile=join(directory,`${name}.pem`),csr=join(directory,`${name}.csr`),extensions=join(directory,`${name}.ext`);
    await writeFile(extensions,`basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=${name==='server'?'serverAuth':'clientAuth'}\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n`);
    await command(openssl,['req','-newkey','rsa:2048','-nodes','-keyout',keyFile,'-out',csr,'-subj',`/CN=${name}`]);
    await command(openssl,['x509','-req','-in',csr,'-CA',caFile,'-CAkey',caKey,'-CAcreateserial','-out',certFile,'-days','2','-extfile',extensions]);
    certificates[name]={keyFile,certFile,fingerprint:new X509Certificate(await readFile(certFile)).fingerprint256.replaceAll(':','').toLowerCase()};
  }
  const server=httpsServer({key:await readFile(certificates.server.keyFile),cert:await readFile(certificates.server.certFile)},(request,response)=>{
    const payload=request.url==='/.well-known/openid-configuration'?{issuer,jwks_uri:`${issuer}/jwks`}:request.url==='/jwks'?jwks:null;
    response.writeHead(payload?200:404,{'content-type':'application/json'}).end(JSON.stringify(payload));
  });
  await new Promise((done)=>server.listen(0,'127.0.0.1',done));const issuer=`https://127.0.0.1:${server.address().port}`;
  return{caFile,certificates,issuer,close:async()=>{await new Promise((done)=>server.close(done));}};
}
