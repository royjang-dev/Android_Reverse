import os
import math
import hashlib
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
ETC = os.path.join(ROOT, 'system', 'system', 'etc')
OUT = os.path.join(ROOT, 'project', '05_framework', 'signing_material.txt')
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
    for x in c:
        if x:
            p = x / n
            e -= p * math.log2(p)
    return round(e, 3)
FILES = ['master.x509.pem', 'ma_cert.dat', 'ma_priv.dat', 'selfsignkey.dat', '0.dat', 'exts.dat', 'pattern.dat', 'defCore.dat']

def try_crypto(name, data):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key, load_der_public_key, load_pem_public_key
    for loader, tag in ((x509.load_pem_x509_certificate, 'PEM cert'), (x509.load_der_x509_certificate, 'DER cert')):
        try:
            c = loader(data)
            L('  -> %s' % tag)
            L('     subject: %s' % c.subject.rfc4514_string())
            L('     issuer : %s' % c.issuer.rfc4514_string())
            L('     serial : %d' % c.serial_number)
            L('     valid  : %s .. %s' % (c.not_valid_before_utc, c.not_valid_after_utc))
            pk = c.public_key()
            L('     pubkey : %s %s-bit' % (type(pk).__name__, getattr(pk, 'key_size', '?')))
            L('     sigalg : %s' % c.signature_algorithm_oid._name)
            return True
        except Exception:
            pass
    for loader, tag in ((load_pem_private_key, 'PEM private key'), (load_der_private_key, 'DER private key')):
        try:
            k = loader(data, password=None)
            L('  -> %s: %s %s-bit  (PRIVATE KEY PRESENT ON DEVICE)' % (tag, type(k).__name__, getattr(k, 'key_size', '?')))
            return True
        except Exception:
            pass
    for loader, tag in ((load_pem_public_key, 'PEM public key'), (load_der_public_key, 'DER public key')):
        try:
            k = loader(data)
            L('  -> %s: %s %s-bit' % (tag, type(k).__name__, getattr(k, 'key_size', '?')))
            return True
        except Exception:
            pass
    return False

def main():
    for f in FILES:
        p = os.path.join(ETC, f)
        if not os.path.exists(p):
            L('\n%s : MISSING' % f)
            continue
        data = open(p, 'rb').read()
        L('\n==== %s (%d bytes, entropy %.2f, sha256 %s) ====' % (f, len(data), ent(data), hashlib.sha256(data).hexdigest()[:16]))
        head = data[:16]
        L('  head: %s' % ' '.join(('%02x' % b for b in head)))
        ok = False
        try:
            ok = try_crypto(f, data)
        except Exception as e:
            L('  crypto parse error: %s' % e)
        if not ok:
            if data[:1] == b'0':
                L('  looks like DER/ASN.1 (0x30 SEQUENCE)')
            printable = sum((32 <= b < 127 for b in data)) / len(data)
            L('  printable ratio: %.2f' % printable)
            if printable > 0.85:
                L('  text preview: %r' % data[:120])
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
