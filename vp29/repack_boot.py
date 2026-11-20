#!/usr/bin/env python3
"""Repack a Spreadtrum/Unisoc boot.img (Android header v0) with a new kernel and modules.

Keeps the stock ramdisk (including any Magisk patch), dtb blob and header
parameters, and only replaces the kernel Image and the vendor kernel modules
inside lib/modules. Optionally restores the pre-Magisk ramdisk.
"""

import argparse
import gzip
import hashlib
import io
import os
import struct
import sys

PAGE_ALIGN = 4


def align4(n):
    return (n + 3) & ~3


def page_align(n, page):
    return (n + page - 1) // page * page


def parse_header(data):
    if data[:8] != b'ANDROID!':
        raise SystemExit('not an Android boot image')
    h = {}
    (h['kernel_size'], h['kernel_addr'], h['ramdisk_size'], h['ramdisk_addr'],
     h['second_size'], h['second_addr'], h['tags_addr'], h['page_size'],
     h['dt_size'], h['os_version']) = struct.unpack_from('<10I', data, 8)
    h['name'] = data[0x30:0x40].split(b'\0')[0]
    h['cmdline'] = data[0x40:0x40 + 512].split(b'\0')[0]
    h['id'] = data[0x240:0x260]
    h['extra_cmdline'] = data[0x260:0x260 + 1024].split(b'\0')[0]
    return h


def extract_parts(data, h):
    page = h['page_size']
    k_off = page
    r_off = page_align(k_off + h['kernel_size'], page)
    s_off = page_align(r_off + h['ramdisk_size'], page)
    dt_off = page_align(s_off + h['second_size'], page)
    parts = {
        'kernel': data[k_off:k_off + h['kernel_size']],
        'ramdisk': data[r_off:r_off + h['ramdisk_size']],
        'second': data[s_off:s_off + h['second_size']],
        'dtb': data[dt_off:dt_off + h['dt_size']],
    }
    return parts


def parse_cpio(raw):
    entries = []
    pos = 0
    while True:
        magic = raw[pos:pos + 6]
        if magic not in (b'070701', b'070702'):
            raise SystemExit('bad cpio magic at %d: %r' % (pos, magic))
        hdr = bytearray(raw[pos:pos + 110])
        filesize = int(hdr[54:62], 16)
        namesize = int(hdr[94:102], 16)
        name = raw[pos + 110:pos + 110 + namesize - 1].decode(errors='replace')
        data_start = align4(pos + 110 + namesize)
        filedata = raw[data_start:data_start + filesize]
        entries.append([hdr, name, filedata])
        pos = align4(data_start + filesize)
        if name == 'TRAILER!!!':
            return entries


def build_cpio(entries):
    out = bytearray()
    for hdr, name, filedata in entries:
        hdr = bytearray(hdr)
        hdr[54:62] = b'%08X' % len(filedata)
        out += hdr
        out += name.encode() + b'\0'
        out += b'\0' * ((4 - len(out) % 4) % 4)
        out += filedata
        out += b'\0' * ((4 - len(out) % 4) % 4)
    return bytes(out)


def gzip_bytes(raw):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=9, mtime=0) as f:
        f.write(raw)
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--stock', required=True, help='stock boot.img')
    ap.add_argument('--kernel', required=True, help='new arch/arm64/boot/Image')
    ap.add_argument('--out', required=True)
    ap.add_argument('--mali')
    ap.add_argument('--sprdwl')
    ap.add_argument('--fm')
    ap.add_argument('--bt')
    ap.add_argument('--dtb', help='override the dtb blob (default: copy from stock image)')
    ap.add_argument('--dtb-image', help='take the dtb blob from another boot image')
    ap.add_argument('--clean-magisk', action='store_true',
                    help='restore the pre-Magisk init and drop overlay.d/.backup')
    args = ap.parse_args()

    data = open(args.stock, 'rb').read()
    h = parse_header(data)
    parts = extract_parts(data, h)
    page = h['page_size']
    print('stock header: page=%d kernel=%d ramdisk=%d dt=%d cmdline=%r' %
          (page, h['kernel_size'], h['ramdisk_size'], h['dt_size'], h['cmdline'].decode(errors='replace')))
    print('stock kernel version:', end=' ')
    import re
    m = re.search(rb'Linux version [^\x00]{0,120}', parts['kernel'])
    print((m.group(0) if m else b'?').decode(errors='replace'))

    ramdisk_cpio = gzip.decompress(parts['ramdisk'])
    entries = parse_cpio(ramdisk_cpio)
    print('ramdisk entries:', len(entries))

    if args.clean_magisk:
        backup = next((e for e in entries if e[1] == '.backup/init.xz'), None)
        if backup is None:
            raise SystemExit('--clean-magisk requested but .backup/init.xz not found')
        import lzma
        original_init = lzma.decompress(backup[2])
        drop = []
        for e in entries:
            if e[1] == 'init':
                e[2] = original_init
            if e[1] in ('.backup', 'overlay.d') or e[1].startswith('.backup/') or e[1].startswith('overlay.d/'):
                drop.append(e)
        entries = [e for e in entries if e not in drop]
        print('magisk removed, init restored, dropped', len(drop), 'entries')

    replacements = {
        'mali.ko': args.mali,
        'sprdwl_ng.ko': args.sprdwl,
        'sprd_fm.ko': args.fm,
        'sprdbt_tty.ko': args.bt,
    }
    replaced = set()
    for e in entries:
        if not e[1].startswith('lib/modules/'):
            continue
        base = os.path.basename(e[1])
        path = replacements.get(base)
        if path:
            e[2] = open(path, 'rb').read()
            replaced.add(base)
            print('module %-14s <- %s (%d bytes)' % (base, path, len(e[2])))

    missing = set(replacements) - replaced
    if missing:
        raise SystemExit('missing module replacements: %s' % ', '.join(sorted(missing)))

    new_cpio = build_cpio(entries)
    new_ramdisk = gzip_bytes(new_cpio)
    print('new ramdisk: cpio=%d gzip=%d' % (len(new_cpio), len(new_ramdisk)))

    kernel = open(args.kernel, 'rb').read()
    m = re.search(rb'Linux version [^\x00]{0,120}', kernel)
    print('new kernel version:', (m.group(0) if m else b'?').decode(errors='replace'))

    boot_id = hashlib.sha1()
    boot_id.update(kernel)
    boot_id.update(new_ramdisk)
    id_digest = boot_id.digest()

    if args.dtb_image:
        other = open(args.dtb_image, 'rb').read()
        other_h = parse_header(other)
        dtb = extract_parts(other, other_h)['dtb']
    elif args.dtb:
        dtb = open(args.dtb, 'rb').read()
    else:
        dtb = parts['dtb']
    if len(dtb) != h['dt_size']:
        print('dtb size override: %d -> %d' % (h['dt_size'], len(dtb)))
        h['dt_size'] = len(dtb)

    hdr = bytearray(1632)
    hdr[0:8] = b'ANDROID!'
    struct.pack_into('<10I', hdr, 8,
                     len(kernel), h['kernel_addr'],
                     len(new_ramdisk), h['ramdisk_addr'],
                     h['second_size'], h['second_addr'],
                     h['tags_addr'], page,
                     h['dt_size'], h['os_version'])
    hdr[0x30:0x40] = h['name'].ljust(16, b'\0')[:16]
    hdr[0x40:0x40 + 512] = h['cmdline'].ljust(512, b'\0')[:512]
    hdr[0x240:0x260] = id_digest
    hdr[0x260:0x260 + 1024] = h['extra_cmdline'].ljust(1024, b'\0')[:1024]

    out = bytearray()
    out += hdr + b'\0' * (page_align(len(hdr), page) - len(hdr))
    out += kernel + b'\0' * (page_align(len(kernel), page) - len(kernel))
    out += new_ramdisk + b'\0' * (page_align(len(new_ramdisk), page) - len(new_ramdisk))
    out += parts['second']
    out += b'\0' * (page_align(len(out), page) - len(out))
    out += dtb

    with open(args.out, 'wb') as f:
        f.write(out)
    print('wrote %s (%d bytes)' % (args.out, len(out)))

    check = parse_header(bytes(out))
    assert check['kernel_size'] == len(kernel)
    assert check['ramdisk_size'] == len(new_ramdisk)
    assert check['dt_size'] == h['dt_size']
    print('verify ok: kernel=%d ramdisk=%d dt=%d page=%d' %
          (check['kernel_size'], check['ramdisk_size'], check['dt_size'], check['page_size']))


if __name__ == '__main__':
    main()
