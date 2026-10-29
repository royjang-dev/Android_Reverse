import os
import re
import json
import traceback
from androguard.core.apk import APK
from androguard.core.dex import DEX
ROOT = 'd:\\ReverseEngineering\\dev1_mt6765'
OUT = os.path.join(ROOT, 'project', '03_apps')
os.makedirs(OUT, exist_ok=True)
NS = '{http://schemas.android.com/apk/res/android}'
TARGETS = ['system\\system\\app\\NsSystemShield\\NsSystemShield.apk', 'system\\system\\app\\NsSmartCard\\NsSmartCard.apk', 'system\\system\\priv-app\\NsSystemAssist\\NsSystemAssist.apk', 'system\\system\\priv-app\\AzaleaScanning\\AzaleaScanning.apk', 'system\\system\\priv-app\\AzaleaAntiTheft\\AzaleaAntiTheft.apk', 'system\\system\\priv-app\\AzaleaSystemUpdater\\AzaleaSystemUpdater.apk', 'system\\system\\priv-app\\AzaleaDayChecker\\AzaleaDayChecker.apk', 'system\\system\\priv-app\\AzaleaClassify\\AzaleaClassify.apk']
PATTERNS = {'screen_capture': re.compile('MediaProjection|createVirtualDisplay|screenshot|screencap|SurfaceControl|/dev/graphics|takeScreenshot|VirtualDisplay', re.I), 'fs_scan': re.compile('MediaStore|getExternalStorage|Environment|/sdcard|/storage/emulated|/DCIM|listFiles|walkFileTree|FileObserver|registerContentObserver', re.I), 'signature_trace': re.compile('watermark|signature|\\.sig\\b|\\btrace\\b|fingerprint|digest|MessageDigest|checksum|stamp|verifySign|addSign', re.I), 'pkg_control': re.compile('setApplicationEnabledSetting|deletePackage|installPackage|PackageInstaller|getInstalledPackages|clearApplicationUserData|DevicePolicyManager|setComponentEnabledSetting', re.I), 'exec_root': re.compile('Runtime;->exec|ProcessBuilder|/system/bin/sh|\\bsu\\b|setprop|/system/bin/|reboot|SystemProperties', re.I), 'net_report': re.compile('https?://|HttpURLConnection|OkHttp|Socket|upload|report|/report|sendReport|post\\(|multipart', re.I), 'persist': re.compile('BOOT_COMPLETED|JobScheduler|AlarmManager|WorkManager|startForegroundService|ACTION_SHUTDOWN|USER_PRESENT', re.I), 'crypto': re.compile('AES|RSA|Cipher|SecretKey|IvParameterSpec|keystore|HmacSHA|base64', re.I), 'korean': re.compile('진달래|검열|흔적|서명|봉사기|등록|제재|차단|감시')}

def attr(el, name):
    return el.get(NS + name)

def resolve_components(apk):
    out = []
    try:
        man = apk.get_android_manifest_xml()
    except Exception:
        return out
    app = man.find('application')
    if app is None:
        return out
    for kind in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
        for el in app.findall(kind):
            name = attr(el, 'name')
            exported = attr(el, 'exported')
            perm = attr(el, 'permission')
            actions = []
            for intf in el.findall('intent-filter'):
                for a in intf.findall('action'):
                    actions.append(attr(a, 'name'))
            if exported is None:
                exp = 'default(%s)' % ('true' if actions else 'false')
            else:
                exp = exported
            out.append((kind, name, exp, perm, actions))
    return out

def scan_strings(apk):
    hits = {k: set() for k in PATTERNS}
    all_strings = []
    for name in apk.get_files():
        if name.endswith('.dex'):
            try:
                d = DEX(apk.get_file(name))
                all_strings.extend(d.get_strings())
            except Exception:
                pass
    for s in all_strings:
        try:
            if isinstance(s, bytes):
                s = s.decode('utf-8', 'ignore')
        except Exception:
            continue
        for k, rx in PATTERNS.items():
            if rx.search(s):
                if len(hits[k]) < 60:
                    hits[k].add(s[:160])
    return (hits, len(all_strings))

def analyze(relpath):
    path = os.path.join(ROOT, relpath)
    name = os.path.splitext(os.path.basename(path))[0]
    rep = ['=' * 70, 'APP: %s' % name, 'path: %s' % relpath]
    summary = {'app': name, 'path': relpath}
    try:
        apk = APK(path)
    except Exception as e:
        rep.append('APK parse error: %s' % e)
        open(os.path.join(OUT, name + '.txt'), 'w', encoding='utf-8').write('\n'.join(rep))
        return {'app': name, 'error': str(e)}
    pkg = apk.get_package()
    summary['package'] = pkg
    summary['version'] = '%s (%s)' % (apk.get_androidversion_name(), apk.get_androidversion_code())
    summary['sdk'] = 'min=%s target=%s' % (apk.get_min_sdk_version(), apk.get_target_sdk_version())
    rep += ['package: %s' % pkg, 'label: %s' % apk.get_app_name(), 'version: %s' % summary['version'], 'sdk: %s' % summary['sdk'], 'sharedUserId: %s' % apk.get_attribute_value('manifest', 'sharedUserId')]
    perms = sorted(apk.get_permissions())
    rep.append('\n-- permissions (%d) --' % len(perms))
    rep += ['  ' + p for p in perms]
    summary['permissions'] = perms
    declared = []
    try:
        man = apk.get_android_manifest_xml()
        for p in man.findall('permission'):
            declared.append('%s (prot=%s)' % (attr(p, 'name'), attr(p, 'protectionLevel')))
    except Exception:
        pass
    if declared:
        rep.append('\n-- declared custom permissions --')
        rep += ['  ' + d for d in declared]
    summary['declared_permissions'] = declared
    comps = resolve_components(apk)
    exported = [c for c in comps if str(c[2]).startswith('true') or c[2] == 'default(true)']
    rep.append('\n-- components (%d total, %d exported) --' % (len(comps), len(exported)))
    for kind, cname, exp, perm, actions in comps:
        flag = 'EXPORTED' if str(exp).startswith('true') or exp == 'default(true)' else ''
        line = '  [%s] %s  exported=%s %s' % (kind, cname, exp, flag)
        if perm:
            line += '  perm=%s' % perm
        rep.append(line)
        for a in actions:
            rep.append('        action: %s' % a)
    summary['components_total'] = len(comps)
    summary['components_exported'] = len(exported)
    hits, nstr = scan_strings(apk)
    rep.append('\n-- DEX string-pool behaviour hits (%d strings scanned) --' % nstr)
    bucket_counts = {}
    for k, vals in hits.items():
        bucket_counts[k] = len(vals)
        if vals:
            rep.append('  [%s] (%d)' % (k, len(vals)))
            for v in sorted(vals):
                rep.append('      %s' % v)
    summary['behaviour_counts'] = bucket_counts
    open(os.path.join(OUT, name + '.txt'), 'w', encoding='utf-8').write('\n'.join(rep))
    print('done: %-20s pkg=%s perms=%d comps=%d/%d exported  buckets=%s' % (name, pkg, len(perms), len(exported), len(comps), {k: v for k, v in bucket_counts.items() if v}))
    return summary

def main():
    results = []
    for t in TARGETS:
        try:
            results.append(analyze(t))
        except Exception as e:
            print('FAIL %s: %s' % (t, e))
            traceback.print_exc()
            results.append({'path': t, 'error': str(e)})
    json.dump(results, open(os.path.join(OUT, 'triage_summary.json'), 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    print('\nwrote 03_apps/triage_summary.json + per-app .txt')
if __name__ == '__main__':
    main()
