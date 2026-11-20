#!/usr/bin/env python3
"""Assert that a boot image carries the true stock VP29 dtb."""

import hashlib
import struct
import sys

EXPECT = '74ca112fbd3e2bae2f19353517ce3cc4c2718a7593cb2f76e27c9ca426fde772'


def dtb_of(path):
    data = open(path, 'rb').read()
    page = struct.unpack_from('<I', data, 0x24)[0]
    ks = struct.unpack_from('<I', data, 8)[0]
    rs = struct.unpack_from('<I', data, 0x10)[0]
    ss = struct.unpack_from('<I', data, 0x18)[0]
    ds = struct.unpack_from('<I', data, 0x28)[0]
    def pa(n):
        return (n + page - 1) // page * page
    off = pa(pa(page + ks) + rs)
    return data[off:off + ds]


def main():
    bad = 0
    for img in sys.argv[1:]:
        blob = dtb_of(img)
        got = hashlib.sha256(blob).hexdigest()
        status = 'STOCK' if got == EXPECT else 'MISMATCH'
        print('%-32s %s  %s  (%d bytes)' % (img, got, status, len(blob)))
        if got != EXPECT:
            bad += 1
    if bad:
        raise SystemExit('%d image(s) do not carry the true stock dtb' % bad)
    print('all images carry the true stock dtb:', EXPECT)


if __name__ == '__main__':
    main()
