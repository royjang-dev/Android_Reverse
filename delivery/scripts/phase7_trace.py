import os
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
LIB = os.path.join(ROOT, 'system\\system\\lib64\\liblegacymsssign.so')
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'phase7_trace.txt')
out = []

def L(s=''):
    print(s)
    out.append(str(s))
b = lief.parse(LIB)
segs = [(s.virtual_address, s.virtual_address + s.virtual_size, s.file_offset) for s in b.segments if s.virtual_size]
raw = open(LIB, 'rb').read()

def rd(va, n):
    for vs, ve, fo in segs:
        if vs <= va < ve:
            o = fo + (va - vs)
            return raw[o:o + n]
    return b''
func_names = {}
for f in b.exported_functions:
    try:
        func_names[f.address] = str(f.name)
    except Exception:
        pass
try:
    for s in b.dynamic_symbols:
        if s.value and s.name:
            func_names.setdefault(s.value, s.name)
except Exception:
    pass

def cstr(va):
    d = rd(va, 64)
    z = d.find(b'\x00')
    s = d[:z if z >= 0 else 64]
    try:
        return s.decode('latin1')
    except Exception:
        return repr(s)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def trace(start, end):
    L('\n==== trace 0x%x .. 0x%x ====' % (start, end))
    code = rd(start, end - start)
    adrp = {}
    for ins in md.disasm(code, start):
        note = ''
        if ins.mnemonic == 'adrp':
            try:
                reg = ins.op_str.split(',')[0].strip()
                adrp[reg] = int(ins.op_str.split('#')[1], 0)
            except Exception:
                pass
        elif ins.mnemonic == 'add' and '#' in ins.op_str:
            p = [x.strip() for x in ins.op_str.split(',')]
            if len(p) == 3 and p[1] in adrp:
                try:
                    imm = int(p[2].lstrip('#'), 0)
                    va = adrp[p[1]] + imm
                    s = cstr(va)
                    if s and all((32 <= ord(c) < 127 for c in s[:4])):
                        note = '  ; "%s" @0x%x' % (s, va)
                    else:
                        note = '  ; data @0x%x = %s' % (va, rd(va, 16).hex())
                except Exception:
                    pass
        elif ins.mnemonic == 'bl':
            try:
                tgt = int(ins.op_str.lstrip('#'), 0)
                if tgt in func_names:
                    note = '  ; -> %s' % func_names[tgt]
            except Exception:
                pass
        L('  0x%06x: %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, note))

def main():
    trace(47936, 48512)
    L('\nstring @0xc70: %r' % cstr(3184))
    L('string @0xc98: %r' % cstr(3224))
    L('string @0xcb0: %r' % cstr(3248))
    L('string @0xccf8: %r' % cstr(52472))
    L('string @0xd48: %r' % cstr(3400))
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
