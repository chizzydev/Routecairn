"""Disposable loopback-only real runtimes. Only exact signed callback commands
are accepted; no listener, arbitrary shell input, file reads or persistent data.
Input travels over stdin and stdout contains runtime/status receipts only.
"""
import importlib.metadata
import io
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import xml.sax
from xml.sax.handler import ContentHandler, EntityResolver, feature_external_ges

data = json.load(sys.stdin)
if len(data["payload"]) > 4096:
    raise ValueError("fixture input too large")
origin = urllib.parse.urlsplit(data["origin"])
if origin.hostname != "127.0.0.1" or origin.scheme not in ("http", "https"):
    raise ValueError("loopback origin required")
identity = re.compile(re.escape(data["origin"].rstrip("/")) + r"/c/[a-f0-9]{32}/[a-f0-9]{32}")
context = ssl.create_default_context(cafile=data["caPath"]) if data["caPath"] else None
executions = 0

def callback(url):
    global executions
    if not identity.fullmatch(url):
        raise ValueError("callback outside exact signed identity")
    executions += 1
    with urllib.request.urlopen(url, timeout=2, context=context) as response:
        response.read(4096)

class Resolver(EntityResolver):
    def resolveEntity(self, publicId, systemId):
        callback(systemId)
        source = xml.sax.InputSource()
        source.setCharacterStream(io.StringIO("fixture-response"))
        return source

kind, secure, payload = data["kind"], data["secure"], data["payload"]
runtime = ""
if kind == "XXE":
    runtime = "python-sax-expat"
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, not secure)
    parser.setEntityResolver(Resolver())
    parser.setContentHandler(ContentHandler())
    if payload.startswith("<?xml"):
        parser.parse(io.StringIO(payload))
elif kind == "COMMAND_INJECTION":
    runtime = "powershell" if os.name == "nt" else "posix-sh"
    expression = r";Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 '([^']+)'" if os.name == "nt" else r";curl -fsS --max-time 2 '([^']+)'"
    match = re.fullmatch(expression, payload)
    if match and not secure:
        if not identity.fullmatch(match[1]):
            raise ValueError("command origin rejected")
        # Use an actual shell parser. Validation permits only the generated
        # fixed command with a loopback URL of hexadecimal path components.
        if os.name == "nt":
            if origin.scheme != "http":
                raise ValueError("Windows shell fixture requires HTTP")
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Write-Output fixture" + payload + " | Out-Null"], capture_output=True, timeout=5)
        else:
            # curl needs the private lab CA; public deployments use system CAs.
            env = dict(os.environ)
            if data["caPath"]:
                env["CURL_CA_BUNDLE"] = data["caPath"]
            result = subprocess.run(["/bin/sh", "-c", "printf fixture" + payload], capture_output=True, timeout=4, env=env)
        if result.returncode != 0:
            raise ValueError("shell callback failed")
        executions += 1
elif kind == "TEMPLATE_INJECTION":
    from jinja2 import Environment
    from jinja2.sandbox import SandboxedEnvironment
    if importlib.metadata.version("jinja2") != "3.1.6" or importlib.metadata.version("markupsafe") != "3.0.3":
        raise ValueError("pinned Jinja2 runtime required")
    runtime = "jinja2-3.1.6-sandbox" if secure else "jinja2-3.1.6"
    command = re.fullmatch(r"\{\{cycler\.__init__\.__globals__\.os\.popen\('curl -fsS --max-time 2 ([^']+)'\)\.read\(\)\}\}", payload)
    if command:
        if not identity.fullmatch(command[1]):
            raise ValueError("template command origin rejected")
        # Actual Jinja-to-os.popen-to-shell traversal. The exact generated
        # command was validated above and can only reach a signed loopback URL.
        previous = os.environ.get("CURL_CA_BUNDLE")
        previous_path = os.environ.get("PATH", "")
        wrapper = tempfile.TemporaryDirectory(prefix="routecairn-oast-curl-")
        if data["caPath"]:
            os.environ["CURL_CA_BUNDLE"] = data["caPath"]
            if os.name == "nt":
                # Windows Schannel ignores CURL_CA_BUNDLE. Preserve the generated
                # shell command, resolving curl through a temporary CA adapter.
                with open(os.path.join(wrapper.name, "curl.cmd"), "w") as file:
                    file.write('@"%SystemRoot%\\System32\\curl.exe" --cacert "%ROUTECAIRN_OAST_FIXTURE_CA%" %*\n')
                os.environ["ROUTECAIRN_OAST_FIXTURE_CA"] = data["caPath"]
                os.environ["PATH"] = wrapper.name + os.pathsep + previous_path
        try:
            (SandboxedEnvironment() if secure else Environment()).from_string(payload).render()
            if not secure:
                executions += 1
        except Exception:
            if not secure:
                raise
        finally:
            os.environ["PATH"] = previous_path
            os.environ.pop("ROUTECAIRN_OAST_FIXTURE_CA", None)
            wrapper.cleanup()
            if previous is None:
                os.environ.pop("CURL_CA_BUNDLE", None)
            else:
                os.environ["CURL_CA_BUNDLE"] = previous
elif kind == "SSRF":
    runtime = "python-urllib"
    if not secure and identity.fullmatch(payload):
        callback(payload)
else:
    raise ValueError("unknown fixture runtime")
print(json.dumps({"runtime": runtime, "executions": executions}))
