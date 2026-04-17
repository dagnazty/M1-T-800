#!/usr/bin/env python3
"""
Patch libnet80211.a to allow raw 802.11 deauth/disassoc/auth frame injection.

Espressif's Wi-Fi library rejects raw management frames in
`ieee80211_raw_frame_sanity_check()`. `esp_wifi_80211_tx()` calls that function
internally (same .o file: ieee80211_output.o), so -Wl,--wrap cannot override it.
We patch the function prologue to `return 0` (always pass).

RISC-V (esp32c6) compressed replacement:
    c.li  a0, 0    ; 0x4501
    c.jr  ra       ; 0x8082
Little-endian bytes: 01 45 82 80

Usage:
    python tools/patch_deauth.py \\
        esp-idf/components/esp_wifi/lib/esp32c6/libnet80211.a

The script is idempotent: re-running on an already-patched archive is a no-op.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile

SYMBOL = "ieee80211_raw_frame_sanity_check"
OBJECT = "ieee80211_output.o"
# c.li a0, 0 ; c.jr ra  (returns 0)
PATCH_BYTES = bytes([0x01, 0x45, 0x82, 0x80])
RISCV_AR = os.environ.get("RISCV_AR", "riscv32-esp-elf-ar")


def log(msg):
    print("\033[32m[patch_deauth]\033[0m " + msg)


def err(msg):
    print("\033[31m[patch_deauth] " + msg + "\033[0m")


def find_section_offset(obj_path, section_name):
    """Parse a 32-bit little-endian ELF and return the file offset of the
    named section's raw data."""
    with open(obj_path, "rb") as f:
        data = f.read()

    # ELF32 header: e_ident(16) + e_type(2) + e_machine(2) + e_version(4)
    #             + e_entry(4) + e_phoff(4) + e_shoff(4) + e_flags(4)
    #             + e_ehsize(2) + e_phentsize(2) + e_phnum(2)
    #             + e_shentsize(2) + e_shnum(2) + e_shstrndx(2)
    if data[:4] != b"\x7fELF":
        raise RuntimeError("{} is not an ELF file".format(obj_path))
    if data[4] != 1:
        raise RuntimeError("Not a 32-bit ELF")

    (e_shoff, _, _e_ehsize, _e_phentsize, _e_phnum,
     e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<IIHHHHHH", data, 0x20
    )

    def read_shdr(i):
        off = e_shoff + i * e_shentsize
        # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
        # sh_link, sh_info, sh_addralign, sh_entsize
        return struct.unpack_from("<IIIIIIIIII", data, off)

    shstr_shdr = read_shdr(e_shstrndx)
    shstrtab_off = shstr_shdr[4]

    def section_name_at(name_off):
        end = data.index(b"\x00", shstrtab_off + name_off)
        return data[shstrtab_off + name_off:end].decode("ascii", "replace")

    for i in range(e_shnum):
        shdr = read_shdr(i)
        if section_name_at(shdr[0]) == section_name:
            return shdr[4], shdr[5]  # (offset, size)

    return None


def patch_object(obj_path):
    section = ".text." + SYMBOL
    found = find_section_offset(obj_path, section)
    if found is None:
        raise RuntimeError("Section {} not found in {}".format(section, obj_path))

    offset, size = found
    if size < len(PATCH_BYTES):
        raise RuntimeError("Section too small ({} < {})".format(size, len(PATCH_BYTES)))

    with open(obj_path, "rb") as f:
        buf = bytearray(f.read())

    current = bytes(buf[offset:offset + len(PATCH_BYTES)])
    if current == PATCH_BYTES:
        log("{} already patched".format(obj_path))
        return False

    log("patching {} at 0x{:x} (section {}, was {})".format(
        obj_path, offset, section, current.hex(" ")))
    buf[offset:offset + len(PATCH_BYTES)] = PATCH_BYTES
    with open(obj_path, "wb") as f:
        f.write(buf)
    return True


def main():
    if len(sys.argv) != 2:
        err("usage: patch_deauth.py <libnet80211.a>")
        sys.exit(2)

    archive = os.path.abspath(sys.argv[1])
    if not os.path.isfile(archive):
        err("archive not found: {}".format(archive))
        sys.exit(2)

    workdir = tempfile.mkdtemp(prefix="patch_deauth_")
    try:
        # Extract the one object we need.
        subprocess.check_call(
            [RISCV_AR, "x", archive, OBJECT],
            cwd=workdir,
        )
        obj_path = os.path.join(workdir, OBJECT)
        if not os.path.isfile(obj_path):
            err("failed to extract {} from archive".format(OBJECT))
            sys.exit(1)

        changed = patch_object(obj_path)
        if not changed:
            return

        # Replace the object in the archive in place.
        # `ar r` replaces the member while preserving the rest of the archive.
        subprocess.check_call(
            [RISCV_AR, "rs", archive, OBJECT],
            cwd=workdir,
        )
        log("wrote patched member back into {}".format(archive))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
