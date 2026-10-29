import os
import re
import gzip
import glob
import struct
import io
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '02_boot_kernel')
os.makedirs(OUT, exist_ok=True)
log = []

def L(s=''):
    print(s)
    log.append(str(s))

def find(pat):
    m = glob.glob(os.path.join(ROOT, pat))
    return m[0] if m else None

def kernel_recon():
    z = os.path.join(ROOT, 'boot', 'zImage')
    if not os.path.exists(z):
        L('no boot/zImage')
        return
    data = open(z, 'rb').read()
    L('\n==== kernel (boot/zImage, %d bytes) ====' % len(data))
    blobs = [data]
    for m in re.finditer(b'\x1f\x8b\x08', data):
        try:
            d = gzip.GzipFile(fileobj=io.BytesIO(data[m.start():])).read()
            blobs.append(d)
            L('  decompressed embedded gzip @0x%x -> %d bytes' % (m.start(), len(d)))
            break
        except Exception:
            pass
    joined = b'\x00'.join(blobs)
    mver = re.search(b'Linux version [^\\x00\\n]{5,200}', joined)
    L('  banner: %s' % (mver.group().decode('latin1') if mver else '<not found>'))
    feats = [b'CONFIG_', b'selinux', b'dm-verity', b'dm_verity', b'KASLR', b'stack_protector', b'CONFIG_KNOX', b'ANDROID_PARANOID', b'init_on_alloc', b'CFI', b'CONFIG_MTK', b'trustkernel', b'Geniezone', b'gz_', b'CONFIG_RANDOMIZE_BASE']
    found = {}
    for pat in (b'CFI failure', b'dm-verity', b'selinux: ', b'Geniezone', b'TEEI', b'trusty', b'Kinibi', b'microtrust'):
        if pat in joined:
            found[pat.decode('latin1')] = True
    L('  notable strings present: %s' % (', '.join(found) or 'none'))
    for m in re.finditer(b'[45]\\.[0-9]{1,2}\\.[0-9]{1,3}[-+\\w.]*', joined):
        s = m.group().decode('latin1')
        if s.count('.') >= 2 and len(s) < 60:
            L('  candidate kernel release token: %s' % s)
            break

def seccfg():
    p = find('*SECCFG_*')
    if not p:
        L('\n==== seccfg: not found ====')
        return
    b = open(p, 'rb').read()
    L('\n==== seccfg (%s, %d bytes) ====' % (os.path.basename(p), len(b)))
    LKS = {0: 'UNINIT', 1: 'DEFAULT', 2: 'MP_DEFAULT', 3: 'UNLOCK', 4: 'LOCK'}
    tag = b.find(b'AND_SECCFG')
    L("  'AND_SECCFG' tag at: %s" % (hex(tag) if tag >= 0 else 'none'))
    off = b.find(struct.pack('<I', 1296911693))
    if off >= 0:
        L('  magic 0x4D4D4D4D at 0x%x' % off)
        try:
            ver, size, lock, crit = struct.unpack_from('<IIII', b, off + 4)
            L('  seccfg_ver=%d size=%d lock_state=%d(%s) critical_lock=%d(%s)' % (ver, size, lock, LKS.get(lock, '?'), crit, LKS.get(crit, '?')))
        except Exception as e:
            L('  parse error: %s' % e)
    for kw in (b'LOCK STATE', b'unlocked', b'orange', b'green', b'yellow'):
        if kw.lower() in b.lower():
            L('  hint string: %s' % kw.decode())
SURV_KW = re.compile('azalea|jindallae|진달래|\\bns[a-z]*shield|nssystem|nssmartcard|daychecker|classify|scanning|scanner|antitheft|trace|watermark|signature|censor|redflag|kwangmyong', re.I)

def scan_init_and_sepolicy():
    L('\n==== init .rc service hits (surveillance keywords) ====')
    rc_roots = [os.path.join(ROOT, 'boot', 'ramdisk'), os.path.join(ROOT, 'system')]
    rc_files = []
    for r in rc_roots:
        for dp, dn, fn in os.walk(r):
            for n in fn:
                if n.endswith('.rc') or n == 'sepolicy' or n.endswith('_contexts') or n.endswith('.te') or n.endswith('.cil'):
                    rc_files.append(os.path.join(dp, n))
    L('  scanning %d rc/policy/context files' % len(rc_files))
    hits = []
    svc_re = re.compile('^\\s*service\\s+(\\S+)\\s+(\\S+)', re.I)
    for f in rc_files:
        try:
            txt = open(f, 'r', encoding='utf-8', errors='ignore').read()
        except Exception:
            continue
        rel = os.path.relpath(f, ROOT)
        for i, line in enumerate(txt.splitlines()):
            if SURV_KW.search(line):
                hits.append((rel, i + 1, line.strip()[:200]))
    seen = set()
    for rel, ln, line in hits:
        key = (rel, line)
        if key in seen:
            continue
        seen.add(key)
        L('  %s:%d  %s' % (rel, ln, line))
    L('  total keyword hits: %d (unique shown)' % len(seen))

def main():
    kernel_recon()
    seccfg()
    scan_init_and_sepolicy()
    open(os.path.join(OUT, 'phase2_boot.log'), 'w', encoding='utf-8').write('\n'.join(log))
    L('\nwrote 02_boot_kernel/phase2_boot.log')
if __name__ == '__main__':
    main()
