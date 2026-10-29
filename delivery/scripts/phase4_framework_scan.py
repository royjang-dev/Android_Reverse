import os
import zipfile
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
FW = os.path.join(ROOT, 'system', 'system', 'framework')
OUT = os.path.join(ROOT, 'project', '05_framework')
os.makedirs(OUT, exist_ok=True)
MARKERS = [b'org/nss', b'NsEngine', b'nsservice', b'NsService', b'secman', b'isLegalPackage', b'getProtectList', b'hasSystemCorruption', b'org.nss', b'SecManager', b'addHistoryListener', b'VaccineService', b'defApps', b'screenshot']
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def scan_jar(path):
    name = os.path.basename(path)
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:
        return
    hits = {}
    for entry in z.namelist():
        if not entry.endswith('.dex'):
            continue
        try:
            data = z.read(entry)
        except Exception:
            continue
        for m in MARKERS:
            c = data.count(m)
            if c:
                hits.setdefault(m.decode('latin1'), 0)
                hits[m.decode('latin1')] += c
    if hits:
        L('\n[%s]' % name)
        for k, v in sorted(hits.items(), key=lambda x: -x[1]):
            L('    %-22s x%d' % (k, v))
    return hits

def main():
    L('scanning framework jars in %s' % FW)
    jars = sorted([os.path.join(FW, f) for f in os.listdir(FW) if f.endswith('.jar')])
    owners = {}
    for j in jars:
        h = scan_jar(j)
        if h and ('NsEngine' in h or 'org/nss' in h or 'nsservice' in h):
            owners[os.path.basename(j)] = h
    L('\n==== candidate owner jars (contain org.nss / NsEngine / nsservice) ====')
    for k in owners:
        L('  ' + k)
    if not owners:
        L('  none in framework/*.jar -> check services.jar internals / apex / oat boot image')
    open(os.path.join(OUT, 'framework_scan.txt'), 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote 05_framework/framework_scan.txt')
if __name__ == '__main__':
    main()
