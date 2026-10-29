import os
import sys
import math
import hashlib
sys.path.insert(0, os.path.dirname(__file__))
from phase6_emulate_rijndael import Rijndael256
from uc_elf import UcElf
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
ETC = os.path.join(ROOT, 'system', 'system', 'etc')
LEGALREF = 'C:\\Users\\Arizona\\Downloads\\legalref.dat'
OUTDIR = os.path.join(ROOT, 'project', '07_findings')
OUT = os.path.join(OUTDIR, 'decrypt_result.txt')
LIBSIA = os.path.join(ROOT, 'system\\system\\lib64\\libSIA.so')
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def ent(d):
    if not d:
        return 0.0
    c = [0] * 256
    for b in d:
        c[b] += 1
    n = len(d)
    e = 0.0
    for v in c:
        if v:
            p = v / n
            e -= p * math.log2(p)
    return e

def pr(d):
    return sum((1 for b in d if 9 <= b <= 13 or 32 <= b < 127)) / max(1, len(d))

def score(d):
    s = []
    if d[:1] == b'0':
        s.append('DER(0x30)')
    if b'-----BEGIN' in d:
        s.append('PEM')
    if b'RSA' in d or b'*\x86H\x86\xf7\r' in d:
        s.append('RSA-OID')
    if b'KP' in d[:64] or b'NSS' in d[:64] or b'Pyongyang' in d:
        s.append('cert-text')
    e = ent(d[:256])
    if e < 6.5:
        s.append('lowent(%.2f)' % e)
    if pr(d) > 0.85:
        s.append('printable(%.2f)' % pr(d))
    return s

class Pilsung:
    SET = 58096
    ENC = 58024
    DEC = 58072

    def __init__(self):
        self.e = UcElf(LIBSIA)

    def dec(self, key, data, keybits):
        e = self.e
        kp = e.alloc(len(key))
        e.w(kp, key)
        e.call(self.SET, (kp, keybits, 0))
        outb = bytearray()
        for i in range(0, len(data) - 15, 16):
            ip = e.alloc(16)
            op = e.alloc(16)
            e.w(ip, data[i:i + 16])
            e.w(op, b'\x00' * 16)
            e.call(self.DEC, (ip, op))
            outb += e.r(op, 16)
        return bytes(outb)

def main():
    lr = open(LEGALREF, 'rb').read()
    L('legalref.dat (%d bytes): %s' % (len(lr), lr.hex()))
    lr8 = lr[:8]
    keys32 = {'LR+LR': lr + lr, 'LR+zero': (lr + b'\x00' * 16)[:32], 'zero+LR': (b'\x00' * 16 + lr)[:32], 'sha256(LR)': hashlib.sha256(lr).digest(), 'sha256(LR8)': hashlib.sha256(lr8).digest(), 'LR8*4': (lr8 * 4)[:32]}
    keys16 = {'LR': lr, 'LR8*2': (lr8 * 2)[:16], 'sha256(LR)[:16]': hashlib.sha256(lr).digest()[:16]}
    containers = {}
    for f in ('0.dat', 'selfsignkey.dat', 'ma_priv.dat', 'ma_cert.dat', 'defCore.dat'):
        p = os.path.join(ETC, f)
        if os.path.exists(p):
            containers[f] = open(p, 'rb').read()
    rij = Rijndael256()
    pil = Pilsung()
    best = []
    for fname, data in containers.items():
        L('\n################ %s (%d bytes, ent %.3f) ################' % (fname, len(data), ent(data)))
        for off in (0, 8, 16):
            body = data[off:]
            n32 = len(body) // 32 * 32
            n16 = len(body) // 16 * 16
            if n32 >= 32:
                for kn, kv in keys32.items():
                    try:
                        dec = rij.decrypt(kv, body[:n32])
                    except Exception as ex:
                        continue
                    sc = score(dec)
                    if sc:
                        L('  RIJNDAEL off=%d key=%s -> %s  head=%s' % (off, kn, sc, dec[:32].hex()))
                        best.append((fname, 'rij', off, kn, sc, dec))
            if n16 >= 16:
                for kn, kv in keys16.items():
                    for kb in (128,):
                        try:
                            dec = pil.dec(kv, body[:n16], kb)
                        except Exception as ex:
                            continue
                        sc = score(dec)
                        if sc:
                            L('  PILSUNG  off=%d key=%s kb=%d -> %s  head=%s' % (off, kn, kb, sc, dec[:32].hex()))
                            best.append((fname, 'pil', off, kn, sc, dec))
    L('\n==== candidate plaintext dumps ====')
    for fname, cip, off, kn, sc, dec in best:
        if any((x.startswith(('DER', 'PEM', 'RSA', 'cert', 'lowent')) for x in sc)):
            tag = '%s_%s_off%d_%s' % (fname, cip, off, kn.replace('(', '').replace(')', '').replace('*', ''))
            dp = os.path.join(OUTDIR, 'plain_%s.bin' % tag)
            open(dp, 'wb').write(dec)
            L('  wrote %s (%s)' % (dp, sc))
            L('    head: %s' % dec[:64].hex())
    if not best:
        L('\nNo structured plaintext from legalref-derived keys. Key derivation')
        L('likely combines legalref.dat with another input (device id / 0.dat).')
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
