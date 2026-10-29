import os
import math
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
ETC = os.path.join(ROOT, 'system', 'system', 'etc')
LEGALREF = 'C:\\Users\\Arizona\\Downloads\\legalref.dat'
LIB = os.path.join(ROOT, 'system\\system\\lib64\\liblegacymsssign.so')
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'phase7_inspect.txt')
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
    return round(e, 3)

def hexdump(d, n=128):
    lines = []
    for i in range(0, min(len(d), n), 16):
        chunk = d[i:i + 16]
        hexs = ' '.join(('%02x' % b for b in chunk))
        asc = ''.join((chr(b) if 32 <= b < 127 else '.' for b in chunk))
        lines.append('  %04x  %-47s  %s' % (i, hexs, asc))
    return '\n'.join(lines)

def inspect(path, label):
    if not os.path.exists(path):
        L('\n== %s : MISSING (%s)' % (label, path))
        return None
    d = open(path, 'rb').read()
    L('\n==== %s ====' % label)
    L('  path: %s' % path)
    L('  size: %d bytes   entropy: %.3f' % (len(d), ent(d)))
    L(hexdump(d, 160))
    return d

def disasm_func(name, va, count=140):
    b = lief.parse(LIB)
    segs = [(s.virtual_address, s.virtual_address + s.virtual_size, s.file_offset) for s in b.segments if s.virtual_size]

    def rd(va, n):
        for vs, ve, fo in segs:
            if vs <= va < ve:
                with open(LIB, 'rb') as f:
                    f.seek(fo + (va - vs))
                    return f.read(n)
        return b''
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    L('\n==== disasm %s @0x%x ====' % (name, va))
    code = rd(va, count * 4)
    n = 0
    for ins in md.disasm(code, va):
        L('  0x%06x: %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
        n += 1
        if ins.mnemonic == 'ret' and n > 6:
            break
        if n >= count:
            break

def main():
    inspect(LEGALREF, 'legalref.dat (SUPPLIED KEY FILE)')
    inspect(os.path.join(ETC, 'selfsignkey.dat'), 'selfsignkey.dat')
    inspect(os.path.join(ETC, '0.dat'), '0.dat')
    inspect(os.path.join(ETC, 'ma_priv.dat'), 'ma_priv.dat')
    disasm_func('MSSGetSignKey', 37312)
    disasm_func('legalref_caller', 48132, count=160)
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
