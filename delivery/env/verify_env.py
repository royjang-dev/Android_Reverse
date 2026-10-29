import importlib
import sys
EXPECT = {'androguard': '4.1.4', 'capstone': ('5.0.9', '5.0.7'), 'keystone': '0.9.2', 'unicorn': '2.1.4', 'lief': '1.0.0', 'elftools': None, 'construct': '2.10.70', 'cryptography': '48.0.1', 'pefile': '2024.8.26', 'lz4': '4.4.5'}

def getver(mod):
    for a in ('__version__', 'version', '__version_string__'):
        v = getattr(mod, a, None)
        if isinstance(v, str):
            return v
    return None

def main():
    print('%-14s %-12s %-12s %s' % ('package', 'found', 'expected', 'status'))
    print('-' * 52)
    ok = True
    for name, exp in EXPECT.items():
        try:
            m = importlib.import_module(name)
        except Exception as e:
            print('%-14s %-12s %-12s IMPORT-FAIL (%s)' % (name, '-', exp or '-', e))
            ok = False
            continue
        v = getver(m) or '(n/a)'
        exps = exp if isinstance(exp, tuple) else (exp,) if exp else ()
        status = 'PASS' if not exps or any((v.startswith(e) for e in exps)) else 'WARN'
        if status == 'WARN':
            ok = ok
        print('%-14s %-12s %-12s %s' % (name, v, exps[0] if exps else '-', status))
    print('-' * 52)
    print('python:', sys.version.split()[0])
    try:
        import frida
        print('frida :', frida.__version__, '(present; do not use without approval)')
    except Exception:
        print('frida : not installed (fine)')
    print('\nCORE IMPORTS OK' if ok else '\nSOME CORE PACKAGES FAILED - see IMPORT-FAIL above')
    sys.exit(0 if ok else 1)
if __name__ == '__main__':
    main()
