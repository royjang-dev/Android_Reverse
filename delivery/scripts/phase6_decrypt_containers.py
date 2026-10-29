import os
import sys
import math
import hashlib
sys.path.insert(0, os.path.dirname(__file__))
from phase6_emulate_rijndael import Rijndael256
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
ETC = os.path.join(ROOT, 'system', 'system', 'etc')
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'decrypt_attempt.txt')
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def ent(d):
    if not d:
        return 0.0
    c = [0] * 256
    for x in d:
        c[x] += 1
    n = len(d)
    e = 0.0
    for v in c:
        if v:
            p = v / n
            e -= p * math.log2(p)
    return e

def printable_ratio(d):
    return sum((1 for b in d if 9 <= b <= 13 or 32 <= b < 127)) / max(1, len(d))

def looks_plain(d):
    if d[:1] == b'0':
        return 'DER/ASN.1 (0x30)'
    if printable_ratio(d) > 0.85:
        return 'text-like (printable %.2f)' % printable_ratio(d)
    if ent(d[:256]) < 6.0:
        return 'low-entropy (%.2f) - structured' % ent(d[:256])
    return None

def candidate_keys():
    keys = {}
    keys['zero32'] = b'\x00' * 32
    keys['ff32'] = b'\xff' * 32
    try:
        from cryptography import x509
        c = x509.load_pem_x509_certificate(open(os.path.join(ETC, 'master.x509.pem'), 'rb').read())
        n = c.public_key().public_numbers().n
        nb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        keys['master_mod_first32'] = nb[:32]
        keys['master_mod_last32'] = nb[-32:]
        keys['sha256(master_mod)'] = hashlib.sha256(nb).digest()
    except Exception as e:
        L('cert parse: %s' % e)
    for f in ('0.dat', 'ma_priv.dat'):
        p = os.path.join(ETC, f)
        if os.path.exists(p):
            d = open(p, 'rb').read()
            keys['%s[:32]' % f] = (d + b'\x00' * 32)[:32]
            keys['sha256(%s)' % f] = hashlib.sha256(d).digest()
    return keys

def main():
    L('Container decrypt attempt (Rijndael-256 ECB) with candidate keys')
    L('NOTE keyhunt: real key is read from /data/legal/sig/*.dat (device-')
    L('provisioned, not in this system dump). Trivial keys are not expected to work.\n')
    r = Rijndael256()
    keys = candidate_keys()
    L('candidate keys: %s\n' % ', '.join(keys))
    targets = ['selfsignkey.dat', 'defCore.dat']
    for t in targets:
        p = os.path.join(ETC, t)
        data = open(p, 'rb').read()
        n = len(data) // 32 * 32
        blk = data[:n]
        L('==== %s (%d bytes, using %d aligned) ====' % (t, len(data), n))
        L('  ciphertext entropy: %.3f' % ent(data))
        hit = False
        for kn, kv in keys.items():
            try:
                dec = r.decrypt(kv, blk)
            except Exception as e:
                L('  key %-22s ERROR %s' % (kn, e))
                continue
            verdict = looks_plain(dec)
            tag = '  <== PLAINTEXT? ' + verdict if verdict else ''
            L('  key %-22s dec_entropy=%.3f%s' % (kn, ent(dec), tag))
            if verdict:
                hit = True
                L('    head: %s' % dec[:48].hex())
        if not hit:
            L('  -> no candidate key produced plaintext (expected; needs the')
            L('     /data/legal/sig key). Decryptor is ready for the real key.')
        L('')
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('wrote %s' % OUT)
if __name__ == '__main__':
    main()
