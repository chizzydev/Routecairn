"""Owned relational care/claim workflow, deliberately distinct from the Node event projection."""
import http.server,json,sqlite3,sys,threading,os
root,mode=sys.argv[1:]
path=os.path.join(root,'care-domain.sqlite')
if os.path.exists(path):raise RuntimeError('FRESH_EXCLUSIVE_DOMAIN_REQUIRED')
db=sqlite3.connect(path,check_same_thread=False)
db.executescript('CREATE TABLE episodes(id INTEGER PRIMARY KEY,tenant TEXT,revision INTEGER,state TEXT); CREATE TABLE claims(id INTEGER PRIMARY KEY,episode_id INTEGER REFERENCES episodes(id),tenant TEXT,revision INTEGER); CREATE TABLE access_policy(resource TEXT,role TEXT,allowed INTEGER); CREATE TABLE actors(slot TEXT PRIMARY KEY,principal TEXT,tenant TEXT,role TEXT);')
db.execute('INSERT INTO episodes VALUES(17,?,1,?)',('north','APPROVED'));db.execute('INSERT INTO claims VALUES(44,17,?,3)',('north',))
for slot,role,tenant in [('primary','manager','north'),('account_a','member','north'),('account_b','guest','south')]:db.execute('INSERT INTO actors VALUES(?,?,?,?)',(slot,'ledger-'+role,tenant,role))
for role in ['manager','member','guest']:db.execute('INSERT INTO access_policy VALUES(?,?,?)',('claim',role,1 if role=='manager' or mode!='secure' else 0))
db.commit();lock=threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  with lock:
   slot=self.headers.get('Authorization','').removeprefix('Bearer heldout-ledger-');actor=db.execute('SELECT principal,tenant,role FROM actors WHERE slot=?',(slot,)).fetchone();status,body=200,{}
   if self.path=='/identity':status=200 if actor else 401;body=dict(zip(['principal','tenant','role'],actor)) if actor else {}
   elif self.path=='/care/catalog/start':body={'record':{'id':'directory','tenant':'north'},'links':{'related':'/care/source/17'}}
   elif self.path!='/':
    if not actor:status=401
    elif self.path=='/care/source/17':
     row=db.execute('SELECT id,tenant,revision,state FROM episodes WHERE id=?',(17,)).fetchone();body={'record':dict(zip(['id','tenant','version','phase'],row)),'links':{'related':'/care/consumer/44'}}
    elif self.path=='/care/consumer/44':
     allowed=db.execute('SELECT allowed FROM access_policy WHERE resource=? AND role=?',('claim',actor[2])).fetchone()[0]
     if not allowed or (mode=='missing-positive' and slot=='primary'):status=403
     else:
      row=db.execute('SELECT id,episode_id,tenant,revision FROM claims WHERE id=?',(44,)).fetchone();record=dict(zip(['id','parent','tenant','version'],row))
      if mode=='wrong-object' and slot!='primary':record['id']=99;record['parent']=31
      if mode=='stale-version' and slot!='primary':record['version']=2
      if mode=='missing-reference':del record['parent']
      if mode=='type-confusion':record['parent']='17'
      body={'record':record}
    else:status=404
   data=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def do_POST(self):self.send_response(405);self.end_headers()
if sys.stdin.readline().strip()!='START':raise RuntimeError('NATIVE_CUSTODY_BEFORE_LISTEN_REQUIRED')
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();print(json.dumps({'port':server.server_port}),flush=True)
for command in sys.stdin:
 if command.strip()=='FIX':
  with lock:
   if mode!='shared':db.execute("UPDATE access_policy SET allowed=0 WHERE resource='claim' AND role!='manager'");db.commit()
  print('FIXED',flush=True)
 elif command.strip()=='STOP':break
server.shutdown();server.server_close()
with open(os.path.join(root,'DOMAIN_SQLITE_RECEIPT.json'),'x') as f:json.dump({'integrity':db.execute('PRAGMA integrity_check').fetchall(),'foreignKeys':db.execute('PRAGMA foreign_key_check').fetchall(),'episodes':db.execute('SELECT * FROM episodes').fetchall(),'claims':db.execute('SELECT * FROM claims').fetchall(),'policy':db.execute('SELECT * FROM access_policy').fetchall(),'mode':mode},f)
db.close()
