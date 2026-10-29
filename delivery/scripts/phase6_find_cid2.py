import os
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '06_surveillance_analysis', 'cid_search2.txt')
IMAGES = ['eMMC_AT3SGD_299976136_ROM1_product_a_0x31003400_0x225e4000.bin', 'eMMC_AT3SGD_299976136_ROM1_system_ext_a_0x11eb3d400_0x5cc40000.bin', 'eMMC_AT3SGD_299976136_ROM1_vendor_a_0x17b77d400_0x21da7000.bin']
NEEDLES = [b'CID.apk', b'CIDService', b'CIDProvider', b'.cid.', b'com.nss', b'org.nss.activate', b'NsSystemUpdate', b'TraceViewer', b'facecheck', b'FaceCheck', b'faceid', b'FaceID', b'nationalid', b'NationalId', b'mobileid', b'MobileID', b'\xea\xb3\xb5\xeb\xaf\xbc\xec\xa6\x9d', b'identity', b'Identity', b'IdentityManager', b'com.cid', b'cid.apk', b'CID']
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
    counts = {n: 0 for n in NEEDLES}
    samples = {n: [] for n in NEEDLES}
    CH = 32 * 1024 * 1024
    overlap = 64
    with open(path, 'rb') as f:
        prev = b''
        base = 0
        while True:
            chunk = f.read(CH)
            if not chunk:
                break
            buf = prev + chunk
            for n in NEEDLES:
                start = 0
                while True:
                    i = buf.find(n, start)
                    if i < 0:
                        break
                    counts[n] += 1
                    if len(samples[n]) < 3:
                        ctx = buf[max(0, i - 24):i + len(n) + 24]
                        ctx = bytes((c if 32 <= c < 127 else 46 for c in ctx))
                        samples[n].append((base + i - len(prev), ctx.decode('latin1')))
                    start = i + 1
            prev = buf[-overlap:]
            base += len(chunk)
    for n in NEEDLES:
        if counts[n]:
            L('  %-14s x%d' % (n.decode('latin1', 'ignore'), counts[n]))
            for off, ctx in samples[n]:
                L('        @~0x%x  %s' % (off, ctx))

def main():
    for im in IMAGES:
        scan(os.path.join(ROOT, im))
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
