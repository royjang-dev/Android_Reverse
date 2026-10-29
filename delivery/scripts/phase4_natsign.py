import os
import re
import zipfile
import io
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
L64 = os.path.join(ROOT, 'system', 'system', 'lib64')
ETC = os.path.join(ROOT, 'system', 'system', 'etc')
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'natsign_stack.txt')
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def strings(data, n=5):
    return [m.decode('latin1') for m in re.findall(b'[\\x20-\\x7e]{%d,}' % n, data)]
KW = re.compile('/system|/data|\\.dat|\\.pem|sign|verify|cert|priv|key|sha|rsa|ecdsa|p256|aes|magisk|\\bsu\\b|avb|otamap|master|national|self|pattern|ext|hook|watermark|provenance', re.I)
LIBS = ['libmedianatsign.so', 'libmediaselfsign.so', 'liblegacymsssign.so', 'libmediaext.so', 'libnshook.so', 'libSIA.so']

def triage(lib):
    p = os.path.join(L64, lib)
    if not os.path.exists(p):
        L('\n== %s MISSING ==' % lib)
        return
    data = open(p, 'rb').read()
    L('\n================ %s (%d bytes) ================' % (lib, len(data)))
    try:
        import lief
        b = lief.parse(p)
        exps = []
        try:
            exps = [str(f) for f in b.exported_functions]
        except Exception:
            pass
        L('exported functions (%d): %s' % (len(exps), ', '.join(exps[:40])))
        try:
            L('needed: %s' % ', '.join((str(x) for x in b.libraries)))
        except Exception:
            pass
    except Exception as e:
        L('lief failed: %s' % e)
    ss = [s for s in strings(data) if KW.search(s)]
    seen = []
    for s in ss:
        if s not in seen:
            seen.append(s)
    L('key strings (%d):' % len(seen))
    for s in seen[:50]:
        L('    ' + s[:150])

def unpack_control():
    L('\n================ /system/etc/exts.dat (zip) ================')
    p = os.path.join(ETC, 'exts.dat')
    try:
        z = zipfile.ZipFile(io.BytesIO(open(p, 'rb').read()))
        for n in z.namelist():
            L('  entry: %s (%d bytes)' % (n, z.getinfo(n).file_size))
            try:
                body = z.read(n)
                prev = body[:300].decode('latin1', 'ignore')
                L('     preview: %r' % prev)
            except Exception as e:
                L('     read err: %s' % e)
    except Exception as e:
        L('  not a zip / error: %s' % e)
    L('\n================ /system/etc/pattern.dat ================')
    d = open(os.path.join(ETC, 'pattern.dat'), 'rb').read()
    ss = [s for s in strings(d, 3)]
    L('  strings: %s' % ', '.join(ss[:60]))

def main():
    for lib in LIBS:
        triage(lib)
    unpack_control()
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
