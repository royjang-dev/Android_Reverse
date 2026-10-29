import os
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'disasm_crypto.txt')
TARGETS = {'system\\system\\lib64\\liblegacymsssign.so': [('Rijndael256_KeyInit', 34472), ('Rijndael256_EncData', 34100), ('Rijndael256_DecData', 34272)], 'system\\system\\lib64\\libSIA.so': None}
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def disasm(path, funcs, count=90):
    b = lief.parse(path)
    name = os.path.basename(path)
    L('\n' + '#' * 70)
    L('# %s' % name)
    segs = [(s.virtual_address, s.virtual_address + s.virtual_size, s.file_offset) for s in b.segments if s.file_offset or s.virtual_size]

    def read(va, n):
        for vs, ve, fo in segs:
            if vs <= va < ve:
                off = fo + (va - vs)
                with open(path, 'rb') as f:
                    f.seek(off)
                    return f.read(n)
        return b''
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    for fname, va in funcs:
        L('\n==== %s @ 0x%x ====' % (fname, va))
        code = read(va, count * 4)
        if not code:
            L('  <no bytes>')
            continue
        n = 0
        for ins in md.disasm(code, va):
            L('  0x%06x: %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
            n += 1
            if ins.mnemonic == 'ret' and n > 4:
                break
            if n >= count:
                break

def sia_funcs(path):
    b = lief.parse(path)
    want = ('pilsung_expand_key', 'pilsung_expand_roundkey', 'pilsng_set_key_test', 'pilsung_set_key', 'pilsung_encrypt', 'pilsung_crypt_block', 'pilsung_expand_key_test')
    found = []
    for f in b.exported_functions:
        nm = str(f.name) if hasattr(f, 'name') else str(f)
        for w in want:
            if w in nm:
                found.append((nm[:40], f.address))
    try:
        for s in b.dynamic_symbols:
            nm = s.name
            if nm and ('pilsung' in nm or 'pilsng' in nm) and s.value:
                found.append((nm[:40], s.value))
    except Exception:
        pass
    seen = {}
    for nm, a in found:
        seen[a] = nm
    return [(nm, a) for a, nm in seen.items()]

def main():
    lp = os.path.join(ROOT, 'system\\system\\lib64\\liblegacymsssign.so')
    disasm(lp, [('Rijndael256_KeyInit', 34472), ('Rijndael256_EncData', 34100), ('Rijndael256_DecData', 34272)])
    sp = os.path.join(ROOT, 'system\\system\\lib64\\libSIA.so')
    pf = sia_funcs(sp)
    L('\nlibSIA pilsung funcs: %s' % pf)
    disasm(sp, pf[:6])
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
