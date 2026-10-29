import os
import re
import sys
import argparse
ROOT_RE = re.compile('d:\\\\+ReverseEngineering\\\\+dev1_mt6765')
LEGALREF_RE = re.compile('C:\\\\+Users\\\\+Arizona\\\\+Downloads\\\\+legalref\\.dat')
SYSPATH_RE = re.compile('([\'\\"])system\\\\+system\\\\+[^\'\\"]*\\1')

def default_root(scripts_dir):
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(scripts_dir))))

def localize_text(text, new_root, new_legalref):
    text = ROOT_RE.sub(new_root.replace('\\', '/'), text)
    text = LEGALREF_RE.sub(new_legalref.replace('\\', '/'), text)
    text = SYSPATH_RE.sub(lambda m: re.sub('\\\\+', '/', m.group(0)), text)
    return text

def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument('--root', default=os.environ.get('FW_ROOT', default_root(here)))
    ap.add_argument('--legalref', default=os.environ.get('LEGALREF', os.path.join(default_root(here), 'legalref.dat')))
    ap.add_argument('--scripts', default=os.path.join(default_root(here), 'project', 'scripts'))
    ap.add_argument('--revert', action='store_true')
    a = ap.parse_args()
    files = [os.path.join(a.scripts, f) for f in os.listdir(a.scripts) if f.endswith('.py')]
    if a.revert:
        for f in files:
            if os.path.exists(f + '.orig'):
                os.replace(f + '.orig', f)
                print('reverted', os.path.basename(f))
        return
    print('dump ROOT  -> %s' % a.root)
    print('legalref   -> %s' % a.legalref)
    print('scripts    -> %s\n' % a.scripts)
    changed = 0
    for f in files:
        src = open(f, 'r', encoding='utf-8').read()
        new = localize_text(src, a.root, a.legalref)
        if new != src:
            if not os.path.exists(f + '.orig'):
                open(f + '.orig', 'w', encoding='utf-8').write(src)
            open(f, 'w', encoding='utf-8').write(new)
            print('localized', os.path.basename(f))
            changed += 1
    print('\n%d file(s) changed. Backups: *.orig (use --revert to undo).' % changed)
if __name__ == '__main__':
    main()
