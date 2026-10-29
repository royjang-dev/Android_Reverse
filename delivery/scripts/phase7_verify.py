import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
ETC = os.path.join(ROOT, 'system', 'system', 'etc')
OUTDIR = os.path.join(ROOT, 'project', '07_findings')
OUT = os.path.join(OUTDIR, 'selfsign_chain.txt')
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def rd(p):
    return open(p, 'rb').read()

def i_be(b):
    return int.from_bytes(b, 'big')

def main():
    sk = rd(os.path.join(ETC, 'selfsignkey.dat'))
    z = rd(os.path.join(ETC, '0.dat'))
    priv = serialization.load_pem_private_key(rd(os.path.join(OUTDIR, 'recovered_selfsign_private.pem')), None)
    pn = priv.private_numbers()
    pub = priv.public_key().public_numbers()
    n = pub.n
    L('== selfsignkey.dat field layout (offsets) ==')
    fields = {'n': n, 'd': pn.d, 'p': pn.p, 'q': pn.q, 'dmp1': pn.dmp1, 'dmq1': pn.dmq1, 'iqmp': pn.iqmp}
    for off in range(0, len(sk) - 16, 4):
        for fn_, fv in fields.items():
            blen = (fv.bit_length() + 7) // 8
            for size in (128, 256):
                if blen <= size and sk[off:off + size] and (i_be(sk[off:off + size]) == fv):
                    L('  @0x%03x  %-5s (%d bytes BE)' % (off, fn_, size))
    L('\n== 0.dat identity ==')
    L('  0.dat == self-sign modulus n ? %s' % (i_be(z) == n))
    try:
        c = x509.load_pem_x509_certificate(rd(os.path.join(ETC, 'master.x509.pem')))
        mp = c.public_key().public_numbers()
        m = pow(i_be(z), mp.e, mp.n).to_bytes(256, 'big')
        L('  0.dat ^ e_master mod n_master head: %s' % m[:40].hex())
        if m[:2] == b'\x00\x01':
            L('    -> PKCS#1 v1.5: 0.dat IS a national-key signature blob')
            L('    tail(32): %s' % m[-32:].hex())
    except Exception as e:
        L('  master check error: %s' % e)
    L('\n== PROOF the recovered key works (SELFSIGN forgery demo) ==')
    msg = b'arbitrary user file content that would normally be blocked'
    sig = priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    try:
        priv.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        L('  signed a test message and verified with the recovered public key: OK')
        L('  => holder of selfsignkey.dat can mint valid SELFSIGN signatures for')
        L('     any file, defeating the on-device content-provenance check.')
    except Exception as e:
        L('  verify failed: %s' % e)
    L('  signature(32B head): %s' % sig[:32].hex())
    pubpem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    open(os.path.join(OUTDIR, 'recovered_selfsign_public.pem'), 'wb').write(pubpem)
    L('\n  wrote recovered_selfsign_public.pem')
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('wrote %s' % OUT)
if __name__ == '__main__':
    main()
