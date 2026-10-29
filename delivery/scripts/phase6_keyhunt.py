import os
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '04_native_libs', 'keyhunt.txt')
out = []

def L(s=''):
    print(s)
    out.append(str(s))

def load(path):
    b = lief.parse(path)
    text = None
    for s in b.sections:
        if s.name == '.text':
            text = s
    return (b, text)

def find_bl_callers(text, target_va):
    data = bytes(text.content)
    base = text.virtual_address
    callers = []
    for i in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[i:i + 4], 'little')
        if w >> 26 == 37:
            imm = w & 67108863
            if imm & 33554432:
                imm -= 67108864
            pc = base + i
            tgt = pc + imm * 4
            if tgt == target_va:
                callers.append(pc)
    return callers

def section_for(b, va):
    for s in b.sections:
        if s.virtual_address <= va < s.virtual_address + s.size:
            return s
    return None

def read_va(b, va, n):
    s = section_for(b, va)
    if not s:
        return b''
    off = va - s.virtual_address
    return bytes(s.content)[off:off + n]

def dump_caller(b, text, caller_pc, md, back=36):
    data = bytes(text.content)
    base = text.virtual_address
    start = caller_pc - back * 4
    code = data[start - base:caller_pc - base + 4]
    L('  --- caller @0x%x ---' % caller_pc)
    adrp_regs = {}
    for ins in md.disasm(code, start):
        note = ''
        if ins.mnemonic == 'adrp':
            try:
                reg = ins.op_str.split(',')[0].strip()
                page = int(ins.op_str.split('#')[1], 0)
                adrp_regs[reg] = page
            except Exception:
                pass
        if ins.mnemonic in ('add', 'ldr') and '#' in ins.op_str:
            parts = ins.op_str.split(',')
            if ins.mnemonic == 'add' and len(parts) == 3:
                srcreg = parts[1].strip()
                if srcreg in adrp_regs:
                    try:
                        imm = int(parts[2].strip().lstrip('#'), 0)
                        ptr = adrp_regs[srcreg] + imm
                        blob = read_va(b, ptr, 32)
                        if blob and any(blob):
                            note = ' ; -> 0x%x = %s' % (ptr, blob.hex())
                    except Exception:
                        pass
        L('    0x%06x: %-7s %s%s' % (ins.address, ins.mnemonic, ins.op_str, note))

def analyze(path, targets):
    b, text = load(path)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    L('\n' + '#' * 70)
    L('# %s' % os.path.basename(path))
    for name, va in targets:
        callers = find_bl_callers(text, va)
        L('\n== callers of %s @0x%x : %d ==' % (name, va, len(callers)))
        for c in callers[:8]:
            dump_caller(b, text, c, md)

def main():
    analyze(os.path.join(ROOT, 'system\\system\\lib64\\liblegacymsssign.so'), [('Rijndael256_KeyInit', 34472), ('MSSGetSignKey', 37312), ('MSSPutSignKey', 37172)])
    analyze(os.path.join(ROOT, 'system\\system\\lib64\\libSIA.so'), [('pilsng_set_key', 58096), ('pilsung_shakey', 49988)])
    open(OUT, 'w', encoding='utf-8').write('\n'.join(out))
    L('\nwrote %s' % OUT)
if __name__ == '__main__':
    main()
