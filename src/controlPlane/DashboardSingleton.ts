import pg from "pg";
import { controlPlaneConfigFromEnv } from "./ControlPlaneConfig.js";

/** The SQLite dashboard must never be replicated; PostgreSQL fleet ingress can be. */
export async function acquireDashboardSingleton(environment:NodeJS.ProcessEnv=process.env):Promise<{release():Promise<void>;onLost(callback:()=>void):void}> {
  const config=controlPlaneConfigFromEnv(environment);
  if(config.mode==="local")return{release:async()=>{},onLost:()=>{}};
  const database=config.postgres!;
  const client=new pg.Client({connectionString:database.url,connectionTimeoutMillis:5_000,application_name:"routecairn-dashboard-owner",...(database.ssl?{ssl:database.ssl}:{})});
  let released=false,lost=false,callback:(()=>void)|undefined;
  const lose=()=>{if(!released){lost=true;callback?.();}};
  client.on("error",lose);client.on("end",lose);
  await client.connect();
  try {const lock=await client.query<{held:boolean}>("SELECT pg_try_advisory_lock(1740321510) AS held");if(!lock.rows[0]!.held)throw new Error("DASHBOARD_SINGLETON_REQUIRED_USE_FLEET_REPLICAS");}
  catch(error){released=true;await client.end();throw error;}
  return{release:async()=>{if(released)return;released=true;await client.end();},onLost:(next)=>{callback=next;if(lost)callback();}};
}
