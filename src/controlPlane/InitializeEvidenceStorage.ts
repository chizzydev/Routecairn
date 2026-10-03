import { readFile } from "node:fs/promises";
import { S3Client,HeadBucketCommand,CreateBucketCommand,PutBucketVersioningCommand,type BucketLocationConstraint } from "@aws-sdk/client-s3";

/** Explicit bucket administration for the supplied deployment; never invoked during readiness. */
export async function initializeEvidenceStorage():Promise<void> {
  const bucket=process.env.ROUTECAIRN_EVIDENCE_S3_BUCKET;
  if(!bucket||!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket))throw new Error("EVIDENCE_BUCKET_REQUIRED");
  const secret=async(name:string)=>{if(process.env[name]&&process.env[`${name}_FILE`])throw new Error("EVIDENCE_CREDENTIAL_SOURCE_CONFLICT");return process.env[`${name}_FILE`]? (await readFile(process.env[`${name}_FILE`]!,"utf8")).trim():process.env[name];};
  const accessKeyId=await secret("AWS_ACCESS_KEY_ID"),secretAccessKey=await secret("AWS_SECRET_ACCESS_KEY");
  if(Boolean(accessKeyId)!==Boolean(secretAccessKey))throw new Error("EVIDENCE_CREDENTIAL_PAIR_REQUIRED");
  const region=process.env.AWS_REGION??"us-east-1";
  const client=new S3Client({region,...(process.env.ROUTECAIRN_EVIDENCE_S3_ENDPOINT?{endpoint:process.env.ROUTECAIRN_EVIDENCE_S3_ENDPOINT}:{}),forcePathStyle:process.env.ROUTECAIRN_EVIDENCE_S3_PATH_STYLE==="true",...(accessKeyId&&secretAccessKey?{credentials:{accessKeyId,secretAccessKey}}:{})});
  try {
    try {await client.send(new HeadBucketCommand({Bucket:bucket}));}
    catch(error){if((error as{$metadata?:{httpStatusCode?:number}}).$metadata?.httpStatusCode!==404)throw new Error("EVIDENCE_BUCKET_ACCESS_REJECTED");await client.send(new CreateBucketCommand({Bucket:bucket,...(region!=="us-east-1"?{CreateBucketConfiguration:{LocationConstraint:region as BucketLocationConstraint}}:{})}));}
    await client.send(new PutBucketVersioningCommand({Bucket:bucket,VersioningConfiguration:{Status:"Enabled"}}));
  } finally {client.destroy();}
}
