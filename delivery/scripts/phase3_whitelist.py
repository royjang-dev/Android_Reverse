import os
import struct
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '03_apps', 'whitelists.txt')
out = []

def L(s=''):
    print(s)
    out.append(str(s))
defapps = os.path.join(ROOT, 'system', 'system', 'etc', 'defApps.dat')
pkg = os.path.join(ROOT, 'system', 'system', 'etc', 'pkg.dat')
L('== /system/etc/defApps.dat (NsSystemShield allowlist) ==')
if os.path.exists(defapps):
    b = open(defapps, 'rb').read()
    L('size=%d bytes -> %d int32 entries' % (len(b), len(b) // 4))
    L('format: int = (md5(first 32KB of apk)[0..3]) big-endian, per SystemShieldService.a()')
    vals = [struct.unpack_from('>i', b, i)[0] for i in range(0, len(b) - 3, 4)]
    L('entries (hex):')
    line = ''
    for i, v in enumerate(vals):
        line += '%08x ' % (v & 4294967295)
        if (i + 1) % 8 == 0:
            L('  ' + line)
            line = ''
    if line:
        L('  ' + line)
else:
    L('NOT FOUND')
L('\n== /system/etc/pkg.dat (NsSystemAssist screenshot-exempt list) ==')
if os.path.exists(pkg):
    txt = open(pkg, 'r', encoding='utf-8', errors='ignore').read()
    lines = [x.strip() for x in txt.splitlines() if x.strip()]
    L('size=%d bytes, %d package lines' % (os.path.getsize(pkg), len(lines)))
    for l in lines:
        L('  ' + l)
else:
    L('NOT FOUND (only hardcoded exemptions: android, com.android.backupconfirm, org.nss.*)')
open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
print('\nwrote', OUT)
