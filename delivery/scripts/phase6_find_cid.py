import os
import re
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '06_surveillance_analysis', 'cid_search.txt')
os.makedirs(os.path.dirname(OUT), exist_ok=True)
IMAGES = ['eMMC_AT3SGD_299976136_ROM1_product_a_0x31003400_0x225e4000.bin', 'eMMC_AT3SGD_299976136_ROM1_system_ext_a_0x11eb3d400_0x5cc40000.bin', 'eMMC_AT3SGD_299976136_ROM1_vendor_a_0x17b77d400_0x21da7000.bin']
PATS = [b'CID', b'[A-Za-z]+CID[A-Za-z]*', b'Identit\\w*', b'NationalID', b'MobileID', b'FaceId\\w*', b'faceid', b'jumin', b'gongmin', b'ecommerce', b'[A-Za-z]{0,12}\\.apk', b'org\\.nss\\.\\w+', b'com\\.[a-z]+\\.cid\\w*', b'CID\\.apk', b'TraceViewer', b'NsSystemUpdate']
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def scan(path):
    L('\n==== %s ====' % os.path.basename(path))
    if not os.path.exists(path):
        L('  MISSING')
        return
    size = os.path.getsize(path)
    L('  size=%d' % size)
    hits = {}
    CH = 16 * 1024 * 1024
    with open(path, 'rb') as f:
        prev = b''
        off = 0
        while True:
            chunk = f.read(CH)
            if not chunk:
                break
            buf = prev + chunk
            for pat in (b'CID\\.apk', b'TraceViewer', b'NsSystemUpdate', b'[A-Za-z0-9_]*[Ii]dentity[A-Za-z0-9_]*', b'[A-Za-z0-9_]*[Ff]ace[A-Za-z0-9_]*', b'com\\.[a-z0-9_.]*cid[a-z0-9_.]*', b'org\\.nss\\.[a-z0-9_]+'):
                for m in re.finditer(pat, buf):
                    s = m.group().decode('latin1', 'ignore')
                    if 3 <= len(s) <= 60:
                        hits[s] = hits.get(s, 0) + 1
            prev = buf[-64:]
            off += len(chunk)
    for s, c in sorted(hits.items(), key=lambda x: (-x[1], x[0]))[:120]:
        L('  %5d  %s' % (c, s))

def main():
    for im in IMAGES:
        scan(os.path.join(ROOT, im))
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
