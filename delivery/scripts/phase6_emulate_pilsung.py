import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from uc_elf import UcElf
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
LIB = os.path.join(ROOT, 'system\\system\\lib64\\libSIA.so')
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'emu_pilsung.txt')
SET_KEY = 58096
ENC_ONE_BLK = 58024
DEC_ONE_BLK = 58072
EXPAND_KEY = 57592
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def hx(b):
    return b.hex()

def main():
    L('Emulating Pilsung (DPRK national cipher) from libSIA.so')
    e = UcElf(LIB, verbose=True)
    key = bytes(range(32))
    blk = bytes(range(16))
    keyp = e.alloc(32)
    e.w(keyp, key)
    inp = e.alloc(16)
    e.w(inp, blk)
    outp = e.alloc(16)
    e.w(outp, b'\x00' * 16)
    L('key : %s' % hx(key))
    L('pt  : %s' % hx(blk))
    for a, b in ((256, 0), (32, 0), (16, 0), (0, 0)):
        try:
            rv = e.call(SET_KEY, (keyp, a, b))
            L('set_key(key, %d, %d) -> %d' % (a, b, rv))
            break
        except Exception as ex:
            L('set_key(key, %d, %d) FAILED: %s' % (a, b, ex))
    try:
        e.w(outp, b'\x00' * 16)
        e.call(ENC_ONE_BLK, (inp, outp))
        ct = e.r(outp, 16)
        L('ct  : %s' % hx(ct))
        dp = e.alloc(16)
        e.w(dp, b'\x00' * 16)
        ctp = e.alloc(16)
        e.w(ctp, ct)
        e.call(DEC_ONE_BLK, (ctp, dp))
        back = e.r(dp, 16)
        L('dec : %s' % hx(back))
        L('ROUND-TRIP %s' % ('OK' if back == blk else 'mismatch (key sched sensitive)'))
    except Exception as ex:
        L('encrypt/decrypt FAILED: %s' % ex)
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
