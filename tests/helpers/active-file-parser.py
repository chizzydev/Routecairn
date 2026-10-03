"""Read tiny fixtures with independent standard parsers; never extract archives.
This simulates owned parser policies, not an external application exploit."""
import base64, csv, io, json, re, sys, tarfile, zipfile
import xml.etree.ElementTree as ET

value = json.loads(sys.stdin.buffer.read(131072))
data = base64.b64decode(value["data"], validate=True)
if len(data) > 65536:
    raise ValueError("fixture limit")
fmt = value["format"]
nonce = re.search(rb"(?:RC_|control-|routecairn-)([a-f0-9]{24})", data)
observed = False
rendered = None
if fmt in ("ZIP", "TAR", "TAR_GZIP"):
    if fmt == "ZIP":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = [(item.filename, (item.external_attr >> 16) & 0o170000 == 0o120000, archive.read(item)) for item in archive.infolist()]
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz" if fmt == "TAR_GZIP" else "r:") as archive:
            entries = [(item.name, item.issym(), item.linkname.encode() if item.issym() else archive.extractfile(item).read()) for item in archive.getmembers()]
    if sum(len(item[2]) for item in entries) > 4096 or len(entries) > 2:
        raise ValueError("expansion limit")
    nonce = re.search(rb"(?:RC_|control-|routecairn-)([a-f0-9]{24})", " ".join(item[0] for item in entries).encode() + b" ".join(item[2] for item in entries))
    effect = value["effect"]
    observed = any(name.startswith("../") for name, _, _ in entries) if effect == "PATH_ESCAPE" else any(link and content.startswith(b"../") for _, link, content in entries) if effect == "SYMLINK_ESCAPE" else len({name for name, _, _ in entries}) != len(entries)
elif fmt == "XML":
    root = ET.fromstring(data)
    observed = b"<!ENTITY" in data and (root.text or "").startswith("RC_")
elif fmt == "SVG":
    root = ET.fromstring(data)
    observed = root.tag == "{http://www.w3.org/2000/svg}svg" and "onload" in root.attrib
    rendered = data.decode() if observed else None
elif fmt == "CSV":
    rows = list(csv.reader(io.StringIO(data.decode())))
    observed = len(rows) == 2 and rows[1][0].startswith('="RC_')
elif fmt == "JSON":
    parsed = json.loads(data)
    observed = parsed["approved"] is True
elif fmt == "PDF":
    import pypdf
    if pypdf.__version__ != "6.19.0":
        raise ValueError("PDF parser version differs from the retained provenance")
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data), strict=False)
    # pypdf keeps the first duplicate title; a policy relying on a downstream
    # last-key-wins parser sees a different value. Retain both actual decisions.
    first = str(reader.metadata.title)
    titles = re.findall(rb"/Title\s+\(([^)]*)\)", data)
    observed = len(titles) == 2 and first == titles[0].decode() and titles[-1].startswith(b"RC_") and titles[0] != titles[-1]
else:
    raise ValueError("unknown format")
if not nonce:
    raise ValueError("unbound fixture")
receipt = {"canary": nonce[1].decode(), "effect": value["effect"], "observed": observed and not value.get("secure", False)}
if rendered and not value.get("secure", False):
    receipt["renderedHtml"] = rendered
print(json.dumps(receipt))
