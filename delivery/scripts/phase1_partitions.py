import os
import glob
import struct
import hashlib
import json
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '01_partitions')
os.makedirs(OUT, exist_ok=True)
log_lines = []

def log(s=''):
    print(s)
    log_lines.append(str(s))

def find(pat):
    m = glob.glob(os.path.join(ROOT, pat))
    return m[0] if m else None

def parse_gpt(path):
    log('\n==== GPT (%s) ====' % os.path.basename(path))
    with open(path, 'rb') as f:
        blob = f.read()
    for ss in (512, 4096):
        hdr = blob[ss:ss + 92]
        if hdr[:8] == b'EFI PART':
            log('sector size: %d' % ss)
            sig, rev, hsize, hcrc, _r, cur_lba, bak_lba, first_lba, last_lba = struct.unpack_from('<8sIII I QQQQ', hdr, 0)
            part_entry_lba = struct.unpack_from('<Q', hdr, 72)[0]
            num_entries = struct.unpack_from('<I', hdr, 80)[0]
            entry_size = struct.unpack_from('<I', hdr, 84)[0]
            log('revision=0x%08x header_size=%d entries=%d entry_size=%d' % (rev, hsize, num_entries, entry_size))
            log('first_usable_lba=%d last_usable_lba=%d' % (first_lba, last_lba))
            entries = []
            base = part_entry_lba * ss
            for i in range(num_entries):
                e = blob[base + i * entry_size:base + (i + 1) * entry_size]
                if len(e) < 56:
                    break
                type_guid = e[0:16]
                if type_guid == b'\x00' * 16:
                    continue
                first = struct.unpack_from('<Q', e, 32)[0]
                last = struct.unpack_from('<Q', e, 40)[0]
                name = e[56:128].decode('utf-16-le', 'ignore').rstrip('\x00')
                sectors = last - first + 1
                entries.append({'index': i, 'name': name, 'first_lba': first, 'last_lba': last, 'size_bytes': sectors * ss, 'offset_bytes': first * ss})
            log('partitions found: %d' % len(entries))
            log('%-20s %14s %14s %14s' % ('name', 'first_lba', 'sectors', 'size_MiB'))
            for e in entries:
                log('%-20s %14d %14d %14.2f' % (e['name'], e['first_lba'], e['last_lba'] - e['first_lba'] + 1, e['size_bytes'] / 1024 / 1024))
            return entries
    log('EFI PART signature not found at sector 512/4096')
    return []

def parse_boot(path, label):
    if not path:
        return None
    with open(path, 'rb') as f:
        b = f.read(4096)
    if b[:8] != b'ANDROID!' and b[:8] != b'VNDRBOOT':
        log('\n==== %s: no boot magic (first8=%r) ====' % (label, b[:8]))
        return None
    log('\n==== %s (%s) ====' % (label, os.path.basename(path)))
    ver = struct.unpack_from('<I', b, 40)[0]
    info = {'label': label, 'magic': b[:8].decode(), 'header_version': ver}
    if b[:8] == b'ANDROID!':
        if ver <= 2:
            ks, ka, rs, ra, ss2, sa, ta, ps, hv, osv = struct.unpack_from('<10I', b, 8)
            name = b[48:64].split(b'\x00')[0].decode('latin1')
            cmdline = b[64:64 + 512].split(b'\x00')[0].decode('latin1')
            info.update(kernel_size=ks, ramdisk_size=rs, second_size=ss2, page_size=ps, os_version=osv, name=name, cmdline=cmdline)
        else:
            ks, rs, osv, hsz = struct.unpack_from('<4I', b, 8)
            cmdline = b[44:44 + 1536].split(b'\x00')[0].decode('latin1')
            info.update(kernel_size=ks, ramdisk_size=rs, os_version=osv, header_size=hsz, cmdline=cmdline)
    else:
        hsz, = struct.unpack_from('<I', b, 8)
        ps, ka, ra, vrs = struct.unpack_from('<4I', b, 12)
        cmdline = b[28:28 + 2048].split(b'\x00')[0].decode('latin1')
        info.update(page_size=ps, vendor_ramdisk_size=vrs, cmdline=cmdline)
    if 'os_version' in info and info['os_version']:
        v = info['os_version']
        ver_bits = v >> 11
        pat_bits = v & 2047
        a = ver_bits >> 14 & 127
        bb = ver_bits >> 7 & 127
        c = ver_bits & 127
        y = (pat_bits >> 4) + 2000
        mo = pat_bits & 15
        info['os_version_decoded'] = '%d.%d.%d patch %04d-%02d' % (a, bb, c, y, mo)
    for k, val in info.items():
        log('  %-20s %s' % (k, val))
    return info
AVB_ALGO = {0: 'NONE (unsigned!)', 1: 'SHA256_RSA2048', 2: 'SHA256_RSA4096', 3: 'SHA256_RSA8192', 4: 'SHA512_RSA2048', 5: 'SHA512_RSA4096', 6: 'SHA512_RSA8192'}
AVB_DESC = {0: 'PROPERTY', 1: 'HASHTREE', 2: 'HASH', 3: 'KERNEL_CMDLINE', 4: 'CHAIN_PARTITION'}

def parse_vbmeta(path, label):
    if not path:
        return None
    with open(path, 'rb') as f:
        b = f.read()
    if b[:4] != b'AVB0':
        log('\n==== %s: not AVB0 (first4=%r) ====' % (label, b[:4]))
        return None
    log('\n==== VBMETA %s (%s) ====' % (label, os.path.basename(path)))
    magic, vmaj, vmin, auth_sz, aux_sz, algo = struct.unpack_from('>4sIIQQI', b, 0)
    hash_off, hash_sz, sig_off, sig_sz, pk_off, pk_sz, pkm_off, pkm_sz, desc_off, desc_sz, rollback = struct.unpack_from('>11Q', b, 32)
    flags, rbl = struct.unpack_from('>II', b, 120)
    release = b[128:128 + 48].split(b'\x00')[0].decode('latin1')
    info = {'label': label, 'libavb': '%d.%d' % (vmaj, vmin), 'algorithm': AVB_ALGO.get(algo, str(algo)), 'rollback_index': rollback, 'rollback_loc': rbl, 'flags': flags, 'release': release, 'auth_block': auth_sz, 'aux_block': aux_sz, 'pubkey_size': pk_sz}
    aux_base = 256 + auth_sz
    if pk_sz:
        pk = b[aux_base + pk_off:aux_base + pk_off + pk_sz]
        info['pubkey_sha256'] = hashlib.sha256(pk).hexdigest()
    fl = []
    if flags & 1:
        fl.append('VERIFICATION_DISABLED')
    if flags & 2:
        fl.append('HASHTREE_DISABLED')
    info['flags_decoded'] = ','.join(fl) if fl else 'none(enforced)'
    descs = []
    p = aux_base + desc_off
    end = p + desc_sz
    while p + 16 <= end:
        tag, nbf = struct.unpack_from('>QQ', b, p)
        body = b[p + 16:p + 16 + nbf]
        d = {'tag': AVB_DESC.get(tag, tag)}
        if tag == 4 and len(body) >= 16:
            rbl2, pname_len, pk_len = struct.unpack_from('>III', body, 0)
            pname = body[12:12 + pname_len].decode('latin1', 'ignore')
            d['chain_partition'] = pname
            d['chain_rollback_loc'] = rbl2
        elif tag == 2 and len(body) >= 16:
            pass
        elif tag == 1:
            pass
        elif tag == 3:
            d['kernel_cmdline'] = body[8:].split(b'\x00')[0].decode('latin1', 'ignore')[:200]
        elif tag == 0:
            d['property_raw'] = body[:80].decode('latin1', 'ignore')
        descs.append(d)
        p += 16 + nbf + -(16 + nbf) % 8
    info['descriptors'] = descs
    for k, val in info.items():
        if k == 'descriptors':
            log('  descriptors (%d):' % len(val))
            for d in val:
                log('      %s' % d)
        else:
            log('  %-20s %s' % (k, val))
    return info

def main():
    results = {}
    gpt = find('*GPTTable0*')
    results['gpt'] = parse_gpt(gpt) if gpt else []
    results['boot'] = []
    for pat, lab in [('*ROM1_BOOT_A_*', 'boot_a'), ('*VENDOR_BOOT_A_*', 'vendor_boot_a'), ('*INIT_BOOT_A_*', 'init_boot_a')]:
        r = parse_boot(find(pat), lab)
        if r:
            results['boot'].append(r)
    results['vbmeta'] = []
    for pat, lab in [('*ROM1_VBMETA_A_*', 'vbmeta'), ('*VBMETA_SYSTEM_A_*', 'vbmeta_system'), ('*VBMETA_VENDOR_A_*', 'vbmeta_vendor')]:
        r = parse_vbmeta(find(pat), lab)
        if r:
            results['vbmeta'].append(r)
    with open(os.path.join(OUT, 'partitions.json'), 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=1)
    with open(os.path.join(OUT, 'phase1_partitions.log'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(log_lines))
    log('\nwrote partitions.json + phase1_partitions.log to %s' % OUT)
if __name__ == '__main__':
    main()
