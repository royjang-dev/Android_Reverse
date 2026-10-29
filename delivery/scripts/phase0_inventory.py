import os
import sys
import csv
import json
import math
import hashlib
import datetime
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
PROJECT = os.path.join(ROOT, 'project')
OUTDIR = os.path.join(PROJECT, '00_inventory')
os.makedirs(OUTDIR, exist_ok=True)
EXCLUDE_DIRS = {PROJECT.lower()}
FULL_HASH_LIMIT = 256 * 1024 * 1024
SAMPLE = 8 * 1024 * 1024
ENTROPY_SAMPLE = 1 * 1024 * 1024
MAGICS = [(0, b'\x7fELF', 'ELF'), (0, b'ANDROID!', 'Android boot image'), (0, b'VNDRBOOT', 'Android vendor_boot'), (0, b'AVB0', 'AVB vbmeta'), (0, b'AVBf', 'AVB footer'), (0, b'BZh', 'bzip2'), (0, b'\x1f\x8b', 'gzip'), (0, b'\x04"M\x18', 'lz4 frame'), (0, b'(\xb5/\xfd', 'zstd'), (0, b'\x89PNG\r\n\x1a\n', 'PNG'), (0, b'\xff\xd8\xff', 'JPEG'), (0, b'PK\x03\x04', 'ZIP/APK/JAR'), (0, b'PK\x05\x06', 'ZIP (empty)'), (0, b'dex\n', 'DEX'), (0, b'cdex', 'CompactDEX'), (0, b'vdex', 'VDEX'), (0, b'oat\n', 'OAT'), (0, b'dey\n', 'DEY (odex)'), (0, b'\xd0\r\xfe\xed', 'DTB (FDT)'), (0, b':\xff&\xed', 'Android sparse image'), (0, b'S\xef', 'ext (superblock magic @0, rare)'), (0, b'MZ', 'PE/DOS'), (0, b"'\x05\x19V", 'uImage (legacy)'), (0, b'070701', 'cpio (newc ascii)'), (0, b'070702', 'cpio (newc crc)'), (0, b'UBI#', 'UBI'), (0, b'\x85\x19', 'JFFS2'), (0, b'hsqs', 'squashfs LE'), (0, b'sqsh', 'squashfs BE'), (0, b'EMMC_BOOT', 'MTK EMMC_BOOT'), (0, b'BOOTLOADER', 'MTK bootloader hdr'), (0, b'\x88\x16\x88X', 'MTK bootimg hdr tag'), (0, b'FILE_INFO', 'MTK FILE_INFO'), (0, b'MMM\x01', 'MTK GFH header (MMM)')]
EXT_SB_OFFSET = 1080

def detect_magic(path, size):
    try:
        with open(path, 'rb') as f:
            head = f.read(4096)
    except Exception as e:
        return f'<read-error: {e}>'
    for off, sig, label in MAGICS:
        if head[off:off + len(sig)] == sig:
            return label
    if size > EXT_SB_OFFSET + 2 and head[EXT_SB_OFFSET:EXT_SB_OFFSET + 2] == b'S\xef':
        return 'ext2/3/4 filesystem'
    if head[:2] == b'\x1f\x9d':
        return 'compress (.Z)'
    if head.strip() == b'' or all((b == 0 for b in head[:512])):
        return 'zero/sparse-start'
    try:
        head.decode('utf-8')
        return 'text/utf-8'
    except Exception:
        pass
    return 'unknown/raw'

def shannon_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)

def hash_file(path, size):
    h = hashlib.sha256()
    mode = 'full'
    try:
        with open(path, 'rb') as f:
            if size <= FULL_HASH_LIMIT:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(chunk)
            else:
                mode = 'head+tail'
                h.update(f.read(SAMPLE))
                if size > SAMPLE:
                    f.seek(max(0, size - SAMPLE))
                    h.update(f.read(SAMPLE))
                h.update(str(size).encode())
    except Exception as e:
        return (f'<hash-error: {e}>', mode)
    return (h.hexdigest(), mode)

def entropy_of(path, size):
    try:
        with open(path, 'rb') as f:
            data = f.read(min(ENTROPY_SAMPLE, size))
        return shannon_entropy(data)
    except Exception:
        return -1.0

def main():
    rows = []
    walked = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        if dirpath.lower().startswith(PROJECT.lower()):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d).lower() not in EXCLUDE_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(full)
            except Exception:
                continue
            rel = os.path.relpath(full, ROOT)
            magic = detect_magic(full, size)
            digest, hmode = hash_file(full, size)
            ent = entropy_of(full, size)
            rows.append({'rel_path': rel, 'size_bytes': size, 'type': magic, 'entropy_1mb': ent, 'sha256': digest, 'hash_mode': hmode, 'ext': os.path.splitext(name)[1].lower()})
            walked += 1
            if walked % 500 == 0:
                print(f'  ...{walked} files', flush=True)
    rows.sort(key=lambda r: -r['size_bytes'])
    csv_path = os.path.join(OUTDIR, 'inventory.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    json_path = os.path.join(OUTDIR, 'inventory.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(rows, f, indent=1)
    by_type = {}
    by_ext = {}
    total = 0
    for r in rows:
        by_type[r['type']] = by_type.get(r['type'], 0) + 1
        by_ext[r['ext'] or '<none>'] = by_ext.get(r['ext'] or '<none>', 0) + 1
        total += r['size_bytes']
    sum_path = os.path.join(OUTDIR, 'phase0_summary.txt')
    with open(sum_path, 'w', encoding='utf-8') as f:
        f.write('Phase 0 inventory summary\n')
        f.write('generated: %s\n' % datetime.datetime.now().isoformat())
        f.write('root: %s\n' % ROOT)
        f.write('files: %d\n' % len(rows))
        f.write('total bytes (sum, incl overlapping raw dumps): %d (%.2f GiB)\n' % (total, total / 1024 / 1024 / 1024))
        f.write('\n== count by detected type ==\n')
        for k, v in sorted(by_type.items(), key=lambda x: -x[1]):
            f.write('%6d  %s\n' % (v, k))
        f.write('\n== count by extension ==\n')
        for k, v in sorted(by_ext.items(), key=lambda x: -x[1]):
            f.write('%6d  %s\n' % (v, k))
        f.write('\n== top 40 largest files ==\n')
        for r in rows[:40]:
            f.write('%14d  %-26s %s\n' % (r['size_bytes'], r['type'], r['rel_path']))
        f.write('\n== high-entropy files >7.5 (compressed/encrypted), >1MB ==\n')
        for r in rows:
            if r['entropy_1mb'] >= 7.5 and r['size_bytes'] > 1024 * 1024:
                f.write('%8.4f  %12d  %-22s %s\n' % (r['entropy_1mb'], r['size_bytes'], r['type'], r['rel_path']))
    print('files:', len(rows))
    print('csv:', csv_path)
    print('json:', json_path)
    print('summary:', sum_path)
if __name__ == '__main__':
    main()
