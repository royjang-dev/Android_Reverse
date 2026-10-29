import os
import math
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
ETC = os.path.join(ROOT, 'system', 'system', 'etc')
LEGALREF = 'C:\\Users\\Arizona\\Downloads\\legalref.dat'
OUTDIR = os.path.join(ROOT, 'project', '07_findings')
OUT = os.path.join(OUTDIR, 'rsa_result.txt')
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def rd(p):
    return open(p, 'rb').read()

def ient(d):
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

def i_be(b):
    return int.from_bytes(b, 'big')

def i_le(b):
    return int.from_bytes(b, 'little')

def is_probable_prime(n, k=12):
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - a // b * y)

def main():
    sk = rd(os.path.join(ETC, 'selfsignkey.dat'))
    z = rd(os.path.join(ETC, '0.dat'))
    lr = rd(LEGALREF)
    L('selfsignkey.dat %d bytes ent %.3f' % (len(sk), ient(sk)))
    L('0.dat           %d bytes ent %.3f' % (len(z), ient(z)))
    L('legalref.dat    %d bytes = %s' % (len(lr), lr.hex()))
    L('legalref as int BE=%d  LE=%d' % (i_be(lr[:8]), i_le(lr[:8])))
    mod_candidates = {'0.dat_BE': i_be(z), '0.dat_LE': i_le(z)}
    for off in range(0, len(sk) - 256 + 1, 4):
        w = sk[off:off + 256]
        if w[0] & 128:
            mod_candidates['sk@0x%x_BE' % off] = i_be(w)
    L('\nscanning selfsignkey for 128-byte prime factors of each modulus...')
    prime_wins = []
    for off in range(0, len(sk) - 128 + 1, 4):
        w = sk[off:off + 128]
        for tag, v in (('BE', i_be(w)), ('LE', i_le(w))):
            if v > 1 and v & 1:
                prime_wins.append((off, tag, v))
    found = None
    for mname, n in mod_candidates.items():
        if n.bit_length() < 2040 or n.bit_length() > 2056:
            continue
        for off, tag, p in prime_wins:
            if p.bit_length() < 1000 or p.bit_length() > 1030:
                continue
            if n % p == 0:
                q = n // p
                if q != 1 and q != n:
                    L('\n*** FACTOR HIT ***')
                    L('modulus = %s (%d bits)' % (mname, n.bit_length()))
                    L('p found in selfsignkey @0x%x (%s), %d bits' % (off, tag, p.bit_length()))
                    L('p prime? %s   q prime? %s' % (is_probable_prime(p), is_probable_prime(q)))
                    found = (n, p, q, mname, off, tag)
                    break
        if found:
            break
    if not found:
        L('\nno direct factor-in-file hit. Trying: does 0.dat verify under the')
        L('MASTER public key (i.e. 0.dat is an RSA signature)?')
        try:
            from cryptography import x509
            c = x509.load_pem_x509_certificate(rd(os.path.join(ETC, 'master.x509.pem')))
            pn = c.public_key().public_numbers()
            for tag, sig in (('BE', i_be(z)), ('LE', i_le(z))):
                m = pow(sig, pn.e, pn.n)
                mb = m.to_bytes(256, 'big')
                L('  0.dat^e mod n_master (%s) head: %s' % (tag, mb[:32].hex()))
                if mb[:2] == b'\x00\x01' and b'\x00' in mb[2:]:
                    L('    -> PKCS#1 v1.5 padding! 0.dat is a master-signed blob.')
        except Exception as e:
            L('  master verify error: %s' % e)
        open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
        L('\nwrote %s' % OUT)
        return
    n, p, q, mname, off, tag = found
    e = 65537
    phi = (p - 1) * (q - 1)
    g, d, _ = egcd(e % phi, phi)
    d %= phi
    L('\nRSA self-sign PRIVATE KEY recovered:')
    L('  n (%d bits): %x' % (n.bit_length(), n))
    L('  e = %d' % e)
    L('  d = %x' % d)
    L('  p = %x' % p)
    L('  q = %x' % q)
    L('  verify: (e*d) mod phi == %d' % (e * d % phi))
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        dp = d % (p - 1)
        dq = d % (q - 1)
        qi = pow(q, -1, p)
        pub = rsa.RSAPublicNumbers(e, n)
        priv = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, pub).private_key()
        pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        kp = os.path.join(OUTDIR, 'recovered_selfsign_private.pem')
        open(kp, 'wb').write(pem)
        L('  wrote %s' % kp)
    except Exception as ex:
        L('  PEM emit error (e may not be 65537): %s' % ex)
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
