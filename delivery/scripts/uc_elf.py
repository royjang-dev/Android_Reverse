import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import *
from unicorn.arm64_const import *
PAGE = 4096

def align_up(x, a=PAGE):
    return x + a - 1 & ~(a - 1)

class UcElf:

    def __init__(self, path, load_bias=1048576, verbose=False):
        self.path = path
        self.bias = load_bias
        self.verbose = verbose
        self.b = lief.parse(path)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self._map_image()
        self._apply_relative_relocs()
        self._setup_stack_heap()
        self._resolve_plt()
        self._install_hooks()

    def _map_image(self):
        maxv = 0
        for s in self.b.segments:
            if int(s.type) == int(lief.ELF.Segment.TYPE.LOAD):
                maxv = max(maxv, s.virtual_address + s.virtual_size)
        self.image_size = align_up(maxv + PAGE)
        self.uc.mem_map(self.bias, self.image_size)
        for s in self.b.segments:
            if int(s.type) == int(lief.ELF.Segment.TYPE.LOAD):
                data = bytes(s.content)
                if data:
                    self.uc.mem_write(self.bias + s.virtual_address, data)
        if self.verbose:
            print('[uc] mapped image @0x%x size 0x%x' % (self.bias, self.image_size))

    def _apply_relative_relocs(self):
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
        R_AARCH64_RELATIVE = 1027
        R_AARCH64_GLOB_DAT = 1025
        R_AARCH64_ABS64 = 257
        n = 0
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not isinstance(sec, RelocationSection):
                    continue
                symtab = elf.get_section(sec['sh_link']) if sec['sh_link'] else None
                for r in sec.iter_relocations():
                    t = r['r_info_type']
                    off = r['r_offset']
                    add = r['r_addend'] if r.is_RELA() else 0
                    if t == R_AARCH64_RELATIVE:
                        val = self.bias + add
                        self.uc.mem_write(self.bias + off, val.to_bytes(8, 'little'))
                        n += 1
                    elif t in (R_AARCH64_GLOB_DAT, R_AARCH64_ABS64) and symtab is not None:
                        sym = symtab.get_symbol(r['r_info_sym'])
                        sval = sym['st_value']
                        if sval:
                            val = self.bias + sval + add
                            self.uc.mem_write(self.bias + off, val.to_bytes(8, 'little'))
                            n += 1
        if self.verbose:
            print('[uc] applied %d data relocs (RELATIVE/GLOB_DAT/ABS64)' % n)

    def _setup_stack_heap(self):
        self.stack_base = 117440512
        self.stack_size = 2097152
        self.uc.mem_map(self.stack_base, self.stack_size)
        self.sp0 = self.stack_base + self.stack_size - 4096
        self.heap_base = 134217728
        self.heap_size = 4194304
        self.uc.mem_map(self.heap_base, self.heap_size)
        self.heap_ptr = self.heap_base
        self.scratch_base = 150994944
        self.scratch_size = 2097152
        self.uc.mem_map(self.scratch_base, self.scratch_size)
        self.scratch_ptr = self.scratch_base
        self.ret_magic = 244837814042624
        self.uc.mem_map(self.ret_magic & ~4095, PAGE)

    def alloc(self, n):
        p = self.scratch_ptr
        self.scratch_ptr += align_up(n, 16)
        return p

    def _resolve_plt(self):
        self.plt_stub = {}
        sec = None
        for s in self.b.sections:
            if s.name == '.plt':
                sec = s
                break
        if sec is None:
            return
        got2sym = {}
        for r in self.b.pltgot_relocations:
            try:
                got2sym[r.address] = r.symbol.name
            except Exception:
                pass
        code = bytes(sec.content)
        base = sec.virtual_address
        off = 32
        while off + 16 <= len(code):
            stub_va = base + off
            insns = list(self.md.disasm(code[off:off + 16], stub_va))
            adrp_page = None
            ldr_off = 0
            for ins in insns:
                if ins.mnemonic == 'adrp':
                    adrp_page = int(ins.op_str.split('#')[1], 0)
                elif ins.mnemonic in ('ldr',) and adrp_page is not None:
                    if '#' in ins.op_str:
                        ldr_off = int(ins.op_str.split('#')[1].rstrip(']'), 0)
                    break
            if adrp_page is not None:
                got = adrp_page + ldr_off
                sym = got2sym.get(got)
                if sym:
                    self.plt_stub[self.bias + stub_va] = sym
            off += 16
        if self.verbose:
            print('[uc] resolved %d plt stubs: %s' % (len(self.plt_stub), sorted(set(self.plt_stub.values()))))

    def _install_hooks(self):
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, self._bad_mem)

    def _bad_mem(self, uc, access, address, size, value, user):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        print('[uc] BAD MEM access=%d addr=0x%x size=%d pc=0x%x (func+0x%x)' % (access, address, size, pc, pc - self.bias))
        try:
            base = address & ~4095
            self.uc.mem_map(base, 4096)
            self.uc.mem_write(base, b'\x00' * 4096)
            return True
        except Exception:
            return False

    def _code_hook(self, uc, address, size, user):
        try:
            self._code_hook_impl(uc, address, size, user)
        except Exception:
            import traceback
            print('[uc] HOOK EXCEPTION at pc=0x%x:' % address)
            traceback.print_exc()
            raise

    def _code_hook_impl(self, uc, address, size, user):
        sym = self.plt_stub.get(address)
        if sym is None:
            return
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        ret = x0
        name = sym.split('@')[0]
        if name in ('memset', '__memset_chk'):
            uc.mem_write(x0, bytes([x1 & 255]) * x2)
            ret = x0
        elif name in ('memcpy', 'memmove', '__memcpy_chk', '__memmove_chk'):
            n = x2 & 4294967295
            if n:
                uc.mem_write(x0, bytes(uc.mem_read(x1, n)))
            ret = x0
        elif name == 'memcmp':
            n = x2 & 4294967295
            a = bytes(uc.mem_read(x0, n))
            b2 = bytes(uc.mem_read(x1, n))
            ret = 0 if a == b2 else 1 if a > b2 else (1 << 64) - 1
        elif name == 'strlen':
            s = b''
            p = x0
            while True:
                c = uc.mem_read(p, 1)
                if c == b'\x00':
                    break
                s += c
                p += 1
            ret = len(s)
        elif name in ('malloc', 'calloc', '_Znwm', '_Znam'):
            n = x0 * x1 if name == 'calloc' else x0
            if n <= 0 or n > self.heap_size:
                n = max(16, min(n & 4294967295, 65536))
            p = self.heap_ptr
            self.heap_ptr += align_up(n, 16)
            if name == 'calloc':
                uc.mem_write(p, b'\x00' * n)
            ret = p
        elif name in ('free', '_ZdlPv', '_ZdaPv'):
            ret = 0
        elif name in ('rand',):
            ret = 4660
        elif name in ('srand', 'time'):
            ret = 0
        elif name in ('printf', 'puts', 'putchar', 'sprintf', 'fprintf', '__android_log_print', 'fwrite'):
            ret = 0
        else:
            if self.verbose:
                print('[uc] stub import %s -> 0' % name)
            ret = 0
        uc.reg_write(UC_ARM64_REG_X0, ret)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def call(self, func_va, args=(), timeout=5000000, max_insn=2000000):
        uc = self.uc
        uc.reg_write(UC_ARM64_REG_SP, self.sp0)
        regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        for i, a in enumerate(args):
            uc.reg_write(regs[i], a & 18446744073709551615)
        uc.reg_write(UC_ARM64_REG_LR, self.ret_magic)
        start = self.bias + func_va
        uc.emu_start(start, self.ret_magic, timeout=timeout, count=max_insn)
        return uc.reg_read(UC_ARM64_REG_X0)

    def w(self, addr, data):
        self.uc.mem_write(addr, bytes(data))

    def r(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))
