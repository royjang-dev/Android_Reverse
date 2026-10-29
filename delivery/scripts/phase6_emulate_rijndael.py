import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from uc_elf import UcElf
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
LIB = os.path.join(ROOT, 'system\\system\\lib64\\liblegacymsssign.so')
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'emu_rijndael.txt')
KEYINIT = 34472
ENCDATA = 34100
DECDATA = 34272
CTX_SIZE = 704
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def hx(b):
    return b.hex()

class Rijndael256:

    def __init__(self, verbose=False):
        self.e = UcElf(LIB, verbose=verbose)

    def _ctx_for(self, key):
        assert len(key) == 32
        e = self.e
        keyp = e.alloc(32)
        ctxp = e.alloc(CTX_SIZE)
        e.w(keyp, key)
        e.w(ctxp, b'\x00' * CTX_SIZE)
        e.call(KEYINIT, (keyp, ctxp))
        return ctxp

    def encrypt(self, key, data):
        e = self.e
        assert len(data) % 32 == 0
        ctxp = self._ctx_for(key)
        datap = e.alloc(len(data))
        lenp = e.alloc(8)
        e.w(datap, data)
        e.w(lenp, len(data).to_bytes(4, 'little'))
        e.call(ENCDATA, (ctxp, datap, lenp))
        return e.r(datap, len(data))

    def decrypt(self, key, data):
        e = self.e
        assert len(data) % 32 == 0
        ctxp = self._ctx_for(key)
        datap = e.alloc(len(data))
        lenp = e.alloc(8)
        e.w(datap, data)
        e.w(lenp, len(data).to_bytes(4, 'little'))
        e.call(DECDATA, (ctxp, datap, lenp))
        return e.r(datap, len(data))

def main():
    L('Emulating Rijndael-256 from liblegacymsssign.so')
    L('API: KeyInit(key[32], ctx[0x2c0]); EncData(ctx, data, &len); DecData(...)')
    L('block = 32 bytes (256-bit), key = 32 bytes (256-bit), ECB\n')
    r = Rijndael256(verbose=True)
    key = bytes(range(32))
    pt = bytes(range(32))
    L('key : %s' % hx(key))
    L('pt  : %s' % hx(pt))
    ct = r.encrypt(key, pt)
    L('ct  : %s' % hx(ct))
    back = r.decrypt(key, ct)
    L('dec : %s' % hx(back))
    L('\nROUND-TRIP %s' % ('OK (dec==pt) -> harness + cipher validated' if back == pt else 'FAILED'))
    ct0 = r.encrypt(b'\x00' * 32, b'\x00' * 32)
    L('\nE(key=0, pt=0) = %s' % hx(ct0))
    L('D(E)==0 : %s' % (r.decrypt(b'\x00' * 32, ct0) == b'\x00' * 32))
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
