import os
import re
import zipfile
from androguard.core.dex import DEX
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
FW = os.path.join(ROOT, 'system', 'system', 'framework')
OUT = os.path.join(ROOT, 'project', '05_framework', 'nss_classes.txt')
RX = re.compile('nss|NsEngine|NsService|SecMan|secman|Vaccine|History|Shield|nationalsign|selfsign|provenance', re.I)
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def classes_in(jarpath):
    found = set()
    try:
        z = zipfile.ZipFile(jarpath)
    except Exception:
        return found
    for entry in z.namelist():
        if not entry.endswith('.dex'):
            continue
        try:
            d = DEX(z.read(entry))
        except Exception:
            continue
        for c in d.get_classes():
            nm = c.get_name()
            if RX.search(nm):
                found.add(nm)
    return found
for jar in ('framework.jar', 'services.jar'):
    p = os.path.join(FW, jar)
    L('\n==== %s ====' % jar)
    cs = sorted(classes_in(p))
    for c in cs:
        dotted = c.strip('L;').replace('/', '.')
        L('  %s' % dotted)
    L('  total: %d' % len(cs))
open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
print('\nwrote', OUT)
