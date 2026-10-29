import os
import re
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '04_native_libs')
os.makedirs(OUT, exist_ok=True)
LIBS = ['system\\system\\lib64\\libnsshield_jni.so', 'system\\system\\lib\\libnsshield_jni.so']
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def ascii_strings(data, minlen=5):
    return re.findall(b'[\\x20-\\x7e]{%d,}' % minlen, data)

def triage(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        L('MISSING %s' % rel)
        return
    data = open(path, 'rb').read()
    L('\n' + '=' * 60)
    L('LIB: %s  (%d bytes)' % (rel, len(data)))
    try:
        import lief
        b = lief.parse(path)
        if b is not None:
            try:
                L('arch: %s  type: %s' % (b.header.machine_type, b.header.file_type))
            except Exception:
                pass
            exp = []
            try:
                for f in b.exported_functions:
                    exp.append(str(f))
            except Exception:
                pass
            if not exp:
                try:
                    for s in b.dynamic_symbols:
                        nm = getattr(s, 'name', '')
                        if nm and ('JNI' in nm or nm.startswith('Java_')):
                            exp.append(nm)
                except Exception:
                    pass
            L('exported/JNI symbols (%d):' % len(exp))
            for e in exp[:60]:
                L('    ' + e)
            try:
                libs = [str(x) for x in b.libraries]
                L('needed libs: %s' % ', '.join(libs))
            except Exception:
                pass
    except Exception as e:
        L('lief parse failed: %s' % e)
    strs = [s.decode('latin1') for s in ascii_strings(data)]
    kw = re.compile('/system|/data|\\.dat|defApps|protect|corrupt|md5|sha|sign|screenshot|property|getprop|reboot|verify|/proc|selinux|avb|dm-verity|NsEngine|\\.so|magisk|su\\b|root', re.I)
    hits = [s for s in strs if kw.search(s)]
    L('\ninteresting strings (%d of %d total):' % (len(hits), len(strs)))
    seen = set()
    for s in hits:
        if s in seen:
            continue
        seen.add(s)
        L('    ' + s[:160])
        if len(seen) > 120:
            break

def main():
    for rel in LIBS:
        triage(rel)
    open(os.path.join(OUT, 'libnsshield_jni.txt'), 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote 04_native_libs/libnsshield_jni.txt')
if __name__ == '__main__':
    main()
