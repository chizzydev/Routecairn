"""Owned synthetic stdlib application; no external I/O, packages or owner data."""
import http.server, json, sqlite3, sys, threading, re, os
root, mode = sys.argv[1:]
path = os.path.join(root, 'application.sqlite')
if os.path.exists(path):
    raise RuntimeError('FRESH_APPLICATION_DB_REQUIRED')
db = sqlite3.connect(path, check_same_thread=False)
db.executescript('CREATE TABLE resources(path TEXT PRIMARY KEY, ref TEXT, category TEXT); CREATE TABLE actors(slot TEXT PRIMARY KEY, principal TEXT, tenant TEXT, role TEXT);')
specs = ['entries/41','rates/2026','balance/current','reports/annual','entries/77','entries/draft']
names = ['restricted','shared','personal','missing','sealed','untyped']
for i, (suffix, category) in enumerate(zip(specs, names)):
    db.execute('INSERT INTO resources VALUES(?,?,?)',('/ledger/'+suffix,'ledger-record-'+str(i),category))
for slot, role, tenant in [('primary','manager','north'),('account_a','member','north'),('account_b','guest','south')]:
    db.execute('INSERT INTO actors VALUES(?,?,?,?)',(slot,'ledger-'+('manager' if slot=='primary' else 'member' if slot=='account_a' else 'guest'),tenant,role))
db.commit()
fixed = False
lock = threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        with lock:
            slot = self.headers.get('Authorization','').removeprefix('Bearer heldout-ledger-')
            actor = db.execute('SELECT principal,tenant,role FROM actors WHERE slot=?',(slot,)).fetchone()
            status, body, html = 200, {}, None
            if self.path == '/identity':
                status = 200 if actor else 401
                body = dict(zip(['principal','tenant','role'],actor)) if actor else {}
            elif self.path == '/ledger/catalog/start':
                links = [p[0] for p in db.execute('SELECT path FROM resources ORDER BY path')]+['/ledger/catalog/pages/2']
                if mode == 'html': html = '<nav>'+''.join('<a href="'+p+'">Open record</a>' for p in links)+'</nav>'
                else: body = {'record':{'entryId':'directory','book':'north'},'data':[{'relationships':{'resource':{'links':{'related':p}}}} for p in links]}
            elif self.path == '/ledger/catalog/pages/2':
                if mode == 'html': html = '<head><link rel="next" href="/ledger/catalog/pages/3"></head><main>Next page</main>'
                else: body = {'record':{'entryId':'page-2','book':'north'},'links':{'next':'/ledger/catalog/pages/3'}}
            elif self.path == '/ledger/catalog/pages/3': body = {'record':{'entryId':'page-3','book':'north'}}
            elif self.path == '/ledger/redirect':
                self.send_response(302); self.send_header('Location','https://external.invalid/never');self.end_headers();return
            elif self.path != '/':
                row = db.execute('SELECT ref,category FROM resources WHERE path=?',(self.path,)).fetchone()
                if not row: status=404
                elif not actor: status=401
                else:
                    ref, category = row
                    if category=='missing' and slot=='primary': status=503
                    elif category=='personal': body={'record':{'entryId':ref if slot=='primary' else 'own-'+slot,'book':actor[1]}}
                    elif category=='untyped': body={'description':'No typed identity available'}
                    elif slot=='primary' or category=='shared' or (category=='restricted' and slot=='account_b' and not fixed): body={'record':{'entryId':ref,'book':'north'}}
                    else: status=403
            data=(html if html is not None else json.dumps(body)).encode()
            self.send_response(status); self.send_header('Content-Type','text/html' if html is not None else ('application/json' if self.path=='/identity' else 'application/vnd.api+json'));self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self): self.send_response(405);self.end_headers()
# No listener exists until the tracked process is attached to its native Job Object.
if sys.stdin.readline().strip() != 'START': raise RuntimeError('CUSTODY_START_REQUIRED')
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
print(json.dumps({'port':server.server_port}),flush=True)
for command in sys.stdin:
    if command.strip()=='FIX':
        with lock: fixed=True
        print('FIXED',flush=True)
    elif command.strip()=='STOP': break
server.shutdown();server.server_close();db.close()
