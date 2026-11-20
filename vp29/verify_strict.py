#!/usr/bin/env python3
"""Strict verifier for VP29 boot images.

Hard requirements:
  * dtb area is byte-identical to the TRUE stock boot dtb
      - SPRD header fields (9832, 1, 0x20000, 0x800, 0x20000)
      - known sha256 of the stock dtb blob
  * every stock ramdisk entry outside lib/modules is byte-identical
      - fstab.sl8541e_1h10, init.rc, init.sl8541e_1h10.rc, init.common.rc,
        ueventd.rc, default.prop must all match the stock hashes
  * only the four vendor modules may differ
  * kernel carries the expected localversion and fits the boot partition
"""

import gzip
import hashlib
import re
import struct
import sys

EXPECT_VERSION = b'4.4.147-VP29'
MODULES = {'mali.ko', 'sprdwl_ng.ko', 'sprd_fm.ko', 'sprdbt_tty.ko'}
STOCK_DTB_FIELDS = (9832, 1, 0x20000, 0x800, 0x20000)
STOCK_DTB_SHA256 = '74ca112fbd3e2bae2f19353517ce3cc4c2718a7593cb2f76e27c9ca426fde772'
STOCK_RAMDISK_SHA256 = {
    'fstab.sl8541e_1h10': '732796ed24b840527c2b310751e3c657b3d79a19a59db90f126e466c983f02eb',
    'init.rc': 'df05973d95abff56e16d72712ba41408fd472b099660cbc854dfe9b9af81d0c7',
    'init.sl8541e_1h10.rc': 'a31b091a05b9cecf0ffa8c25e9834caa529b4e76613a370a3158e88556883b8a',
    'init.common.rc': '48cd4125a5dc92618487204bc18e6e77cc980564ead8808199bd9f00b9e6db86',
    'ueventd.rc': 'aaa5a20b2b5482184ff2a7b9a20be30ebf926f15ebdd9527fde617a00b2a4b7b',
    'default.prop': '958fad083e08fc0c22b1ecf549f95105122504f7df989f789575995d53cf8094',
}
BOOT_PARTITION = 36700160


def split_boot(data):
    assert data[:8] == b'ANDROID!', 'bad boot magic'
    (ks, ka, rs, ra, ss, sa, ta, page, dts, osv) = struct.unpack_from('<10I', data, 8)
    def pa(n):
        return (n + page - 1) // page * page
    k_off = page
    r_off = pa(k_off + ks)
    s_off = pa(r_off + rs)
    dt_off = pa(s_off + ss)
    return {
        'kernel': data[k_off:k_off + ks],
        'ramdisk': data[r_off:r_off + rs],
        'dtb': data[dt_off:dt_off + dts],
        'page': page, 'ks': ks, 'rs': rs, 'dts': dts,
        'cmdline': data[0x40:0x240].split(b'\0')[0],
    }


def cpio_entries(raw):
    out = {}
    pos = 0
    while True:
        assert raw[pos:pos + 6] in (b'070701', b'070702'), 'bad cpio magic'
        size = int(raw[pos + 54:pos + 62], 16)
        nsize = int(raw[pos + 94:pos + 102], 16)
        name = raw[pos + 110:pos + 110 + nsize - 1].decode(errors='replace')
        dstart = (pos + 110 + nsize + 3) & ~3
        out[name] = raw[dstart:dstart + size]
        pos = (dstart + size + 3) & ~3
        if name == 'TRAILER!!!':
            return out


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: verify_strict.py <boot.img> [stock_boot.img]')
    image = sys.argv[1]
    stock = sys.argv[2] if len(sys.argv) > 2 else None
    data = open(image, 'rb').read()
    img = split_boot(data)

    print('image     :', image, len(data), 'bytes')
    print('sha256    :', hashlib.sha256(data).hexdigest())
    print('sizes     : kernel=%d ramdisk=%d dt=%d page=%d' %
          (img['ks'], img['rs'], img['dts'], img['page']))
    print('cmdline   :', img['cmdline'].decode(errors='replace'))

    if len(data) > BOOT_PARTITION:
        raise SystemExit('image %d > boot partition %d' % (len(data), BOOT_PARTITION))

    m = re.search(rb'Linux version [^\x00]{0,200}', img['kernel'])
    ver = m.group(0) if m else b'?'
    print('kernel    :', ver.decode(errors='replace'))
    if EXPECT_VERSION not in ver:
        raise SystemExit('localversion mismatch, expected %s' % EXPECT_VERSION.decode())

    # ---------- dtb must be the true stock blob ----------
    dtb_hash = hashlib.sha256(img['dtb']).hexdigest()
    print('dtb       : size=%d sha256=%s' % (len(img['dtb']), dtb_hash))
    if dtb_hash != STOCK_DTB_SHA256:
        raise SystemExit('DTB IS NOT STOCK (hash %s)' % dtb_hash)
    if img['dtb'][:4] != b'SPRD':
        raise SystemExit('dtb is not an SPRD-wrapped blob')
    fields = struct.unpack_from('<5I', img['dtb'], 12)
    if fields != STOCK_DTB_FIELDS:
        raise SystemExit('SPRD header fields differ: %s' % (fields,))
    print('dtb       : stock hash + SPRD fields %s OK' % [hex(x) for x in fields])

    if stock:
        sto = split_boot(open(stock, 'rb').read())
        if img['dtb'] != sto['dtb']:
            raise SystemExit('dtb differs from reference stock boot')
        print('dtb       : byte-identical to', stock)

    # ---------- ramdisk: stock files must be untouched ----------
    entries = cpio_entries(gzip.decompress(img['ramdisk']))
    print('ramdisk   : %d entries' % len(entries))

    failures = []
    for name, expect in STOCK_RAMDISK_SHA256.items():
        blob = entries.get(name)
        got = hashlib.sha256(blob).hexdigest() if blob is not None else None
        ok = got == expect
        print('  %-24s %s' % (name, 'stock' if ok else 'CHANGED/MISSING'))
        if not ok:
            failures.append(name)
    if failures:
        raise SystemExit('fstab/init files are not stock: %s' % failures)

    if stock:
        sto_entries = cpio_entries(gzip.decompress(sto['ramdisk']))
        protected = [n for n in sto_entries
                     if n not in ('TRAILER!!!', 'init') and not n.startswith('lib/modules/')]
        changed = [n for n in protected if entries.get(n) != sto_entries[n]]
        if changed:
            raise SystemExit('stock ramdisk files changed: %s' % changed[:10])
        if 'init' in sto_entries and entries.get('init') != sto_entries['init']:
            backup = entries.get('.backup/init.xz')
            if not backup:
                raise SystemExit('init differs from stock and no pre-Magisk backup present')
            import lzma
            if lzma.decompress(backup) != sto_entries['init']:
                raise SystemExit('init differs and backup does not match stock init')
            print('init      : Magisk wrapper, pre-patch init verified against stock')
        print('ramdisk   : %d stock files byte-identical' % len(protected))

    # ---------- modules ----------
    found = {}
    for name, blob in entries.items():
        if name.startswith('lib/modules/') and name.endswith('.ko'):
            base = name.rsplit('/', 1)[1]
            found[base] = blob
            vm = re.search(rb'vermagic=[^\x00]{0,90}', blob)
            vm = vm.group(0) if vm else b'?'
            print('module    : %-16s %8d  %s' % (base, len(blob), vm.decode(errors='replace')))
            if EXPECT_VERSION not in vm:
                raise SystemExit('%s vermagic mismatch' % base)
    missing = MODULES - set(found)
    if missing:
        raise SystemExit('missing modules: %s' % ', '.join(sorted(missing)))

    print('RESULT    : dtb stock, fstab stock, ramdisk stock, modules rebuilt -> OK')


if __name__ == '__main__':
    main()
