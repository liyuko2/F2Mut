#!/usr/bin/env python3
"""Example local executor for format-aware ELF mutation plans.

This module is intentionally standalone: it does not call an LLM and it does
not execute the target binary. A fast online model or scheduler can emit small
plans that select from the operations implemented here.

The default profile is derived from binutils_test/in/small_exec.elf:
ELF32, little endian, i386, 2 program headers, 4 section headers.
"""

import argparse
import json
import os
import random
import struct


MAX_OUTPUT_SIZE = 1024 * 1024

EI_CLASS = 4
EI_DATA = 5
ELFCLASS32 = 1
ELFDATA2LSB = 1

ET_REL = 1
ET_EXEC = 2
ET_DYN = 3

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_PHDR = 6
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551

PT_GNU_RELRO = 0x6474E552

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_GROUP = 17


SMALL_EXEC_PROFILE = {
    "name": "small_exec_elf32_lsb_i386",
    "class": "ELF32",
    "endian": "little",
    "machine": EM_386,
    "entry": 0x08048074,
    "ehoff": 0,
    "ehsize": 52,
    "phoff": 52,
    "phentsize": 32,
    "phnum": 2,
    "shoff": 164,
    "shentsize": 40,
    "shnum": 4,
    "shstrndx": 3,
    "regions": {
        ".text": {"offset": 0x74, "size": 0x0C},
        ".data": {"offset": 0x80, "size": 0x0C},
        ".shstrtab": {"offset": 0x8C, "size": 0x17},
    },
}


DEFAULT_PLAN = {
    "template": "elf32_lsb_i386_local_executor",
    "ops": [
        {"op": "ensure_elf32_i386"},
        {"op": "construct_note_section"},
        {"op": "construct_dynamic_section"},
        {"op": "construct_interp_segment"},
        {"op": "construct_gnu_stack_phdr"},
        {"op": "construct_relocation_section"},
        {"op": "construct_hash_table_section"},
        {"op": "mutate_ehdr_enum", "fields": ["e_type", "e_machine"]},
        {"op": "mutate_program_header", "index": "random"},
        {"op": "mutate_section_header", "index": "random"},
        {"op": "mutate_region", "region": ".text", "max_len": 4},
        {"op": "mutate_region", "region": ".data", "max_len": 8},
        {"op": "mutate_shstrtab", "max_len": 8},
        {"op": "append_tail_block", "min_len": 1, "max_len": 64},
        {"op": "sync_elf32_headers"},
    ],
    "limits": {"max_output_size": MAX_OUTPUT_SIZE, "max_ops_per_call": 32},
}


def _u16(buf, off):
    if off < 0 or off + 2 > len(buf):
        return None
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    if off < 0 or off + 4 > len(buf):
        return None
    return struct.unpack_from("<I", buf, off)[0]


def _w16(buf, off, value, max_size):
    if not _ensure_len(buf, off + 2, max_size):
        return False
    struct.pack_into("<H", buf, off, int(value) & 0xFFFF)
    return True


def _w32(buf, off, value, max_size):
    if not _ensure_len(buf, off + 4, max_size):
        return False
    struct.pack_into("<I", buf, off, int(value) & 0xFFFFFFFF)
    return True


def _ensure_len(buf, size, max_size):
    if size < 0 or size > max_size:
        return False
    if len(buf) < size:
        buf.extend(b"\x00" * (size - len(buf)))
    return True


def _is_elf32_lsb(buf):
    return (
        len(buf) >= 16 and
        bytes(buf[:4]) == b"\x7fELF" and
        buf[EI_CLASS] == ELFCLASS32 and
        buf[EI_DATA] == ELFDATA2LSB
    )


def _limit(plan, key, default):
    limits = plan.get("limits", {}) if isinstance(plan, dict) else {}
    try:
        return max(int(limits.get(key, default)), 1)
    except (TypeError, ValueError):
        return default


def _choice(values):
    values = list(values)
    return values[random.randrange(len(values))]


def _bounded_region(profile, region_name, buf_len):
    region = profile.get("regions", {}).get(region_name)
    if not isinstance(region, dict):
        return None
    try:
        start = max(int(region.get("offset", 0)), 0)
        size = max(int(region.get("size", 0)), 0)
    except (TypeError, ValueError):
        return None
    end = min(start + size, buf_len)
    if start >= end:
        return None
    return start, end


def _section_header_offset(profile, index):
    try:
        shoff = int(profile.get("shoff", 0))
        entsize = int(profile.get("shentsize", 40))
        shnum = int(profile.get("shnum", 0))
        index = int(index)
    except (TypeError, ValueError):
        return None
    if index < 0 or index >= shnum:
        return None
    return shoff + index * entsize


def _program_header_offset(profile, index):
    try:
        phoff = int(profile.get("phoff", 0))
        entsize = int(profile.get("phentsize", 32))
        phnum = int(profile.get("phnum", 0))
        index = int(index)
    except (TypeError, ValueError):
        return None
    if index < 0 or index >= phnum:
        return None
    return phoff + index * entsize


def ensure_elf32_i386(buf, profile, max_size):
    if not _ensure_len(buf, int(profile.get("ehsize", 52)), max_size):
        return False
    buf[0:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    _w16(buf, 0x10, ET_EXEC, max_size)
    _w16(buf, 0x12, int(profile.get("machine", EM_386)), max_size)
    _w32(buf, 0x14, 1, max_size)
    _w32(buf, 0x18, int(profile.get("entry", 0x08048074)), max_size)
    _w32(buf, 0x1C, int(profile.get("phoff", 52)), max_size)
    _w32(buf, 0x20, int(profile.get("shoff", 164)), max_size)
    _w32(buf, 0x24, 0, max_size)
    _w16(buf, 0x28, int(profile.get("ehsize", 52)), max_size)
    _w16(buf, 0x2A, int(profile.get("phentsize", 32)), max_size)
    _w16(buf, 0x2C, int(profile.get("phnum", 2)), max_size)
    _w16(buf, 0x2E, int(profile.get("shentsize", 40)), max_size)
    _w16(buf, 0x30, int(profile.get("shnum", 4)), max_size)
    _w16(buf, 0x32, int(profile.get("shstrndx", 3)), max_size)
    min_size = int(profile.get("shoff", 164)) + int(profile.get("shentsize", 40)) * int(profile.get("shnum", 4))
    return _ensure_len(buf, min_size, max_size)


def mutate_ehdr_enum(buf, op, _profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    fields = op.get("fields", ["e_type", "e_machine", "e_entry"])
    if not isinstance(fields, list) or not fields:
        fields = ["e_type", "e_machine", "e_entry"]
    field = _choice(fields)
    if field == "e_type":
        return _w16(buf, 0x10, _choice([ET_REL, ET_EXEC, ET_DYN]), max_size)
    if field == "e_machine":
        return _w16(buf, 0x12, _choice([EM_386, EM_ARM, EM_X86_64, EM_AARCH64]), max_size)
    if field == "e_entry":
        base = _u32(buf, 0x18)
        if base is None:
            return False
        return _w32(buf, 0x18, base + _choice([-16, -4, 0, 4, 16, 0x100]), max_size)
    return False


def mutate_program_header(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    phnum = max(int(profile.get("phnum", 0)), 0)
    if phnum <= 0:
        return False
    index = op.get("index", "random")
    if index == "random":
        index = random.randrange(phnum)
    off = _program_header_offset(profile, index)
    if off is None or off + 32 > len(buf):
        return False
    field = _choice(op.get("fields", ["p_type", "p_flags", "p_align", "p_filesz"]))
    if field == "p_type":
        return _w32(buf, off + 0x00, _choice([PT_NULL, PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR, PT_GNU_EH_FRAME, PT_GNU_STACK]), max_size)
    if field == "p_flags":
        return _w32(buf, off + 0x18, _choice([0, 1, 2, 3, 4, 5, 6, 7]), max_size)
    if field == "p_align":
        return _w32(buf, off + 0x1C, _choice([0, 1, 4, 16, 0x1000]), max_size)
    if field == "p_filesz":
        p_offset = _u32(buf, off + 0x04)
        if p_offset is None or p_offset >= len(buf):
            return False
        remaining = len(buf) - p_offset
        new_size = random.randrange(0, min(remaining, 0x1000) + 1)
        _w32(buf, off + 0x10, new_size, max_size)
        return _w32(buf, off + 0x14, max(new_size, _u32(buf, off + 0x14) or 0), max_size)
    return False


def mutate_section_header(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    shnum = max(int(profile.get("shnum", 0)), 0)
    if shnum <= 1:
        return False
    index = op.get("index", "random")
    if index == "random":
        index = random.randrange(1, shnum)
    off = _section_header_offset(profile, index)
    if off is None or off + 40 > len(buf):
        return False
    field = _choice(op.get("fields", ["sh_type", "sh_flags", "sh_addralign", "sh_entsize"]))
    if field == "sh_type":
        return _w32(buf, off + 0x04, _choice([SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_HASH, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_REL, SHT_DYNSYM, SHT_INIT_ARRAY, SHT_GROUP]), max_size)
    if field == "sh_flags":
        return _w32(buf, off + 0x08, _choice([0, 1, 2, 3, 4, 6, 0x10, 0x30, 0x80000000]), max_size)
    if field == "sh_addralign":
        return _w32(buf, off + 0x20, _choice([0, 1, 2, 4, 8, 16, 0x1000]), max_size)
    if field == "sh_entsize":
        return _w32(buf, off + 0x24, _choice([0, 1, 4, 8, 12, 16, 24, 32]), max_size)
    return False


def mutate_region(buf, op, profile, _max_size):
    region_name = op.get("region", ".text")
    region = _bounded_region(profile, region_name, len(buf))
    if region is None:
        return False
    start, end = region
    max_len = max(int(op.get("max_len", 8)), 1)
    length = random.randrange(1, min(max_len, end - start) + 1)
    pos = random.randrange(start, end - length + 1)
    mode = _choice(op.get("modes", ["bitflip", "arith", "random"]))
    for idx in range(pos, pos + length):
        if mode == "bitflip":
            buf[idx] ^= 1 << random.randrange(8)
        elif mode == "arith":
            buf[idx] = (buf[idx] + _choice([-16, -3, -1, 1, 3, 16])) & 0xFF
        else:
            buf[idx] = random.getrandbits(8)
    return True


def mutate_shstrtab(buf, op, profile, _max_size):
    region = _bounded_region(profile, ".shstrtab", len(buf))
    if region is None:
        return False
    start, end = region
    mutable_positions = [idx for idx in range(start, end) if buf[idx] not in (0, ord("."))]
    if not mutable_positions:
        return False
    max_len = max(int(op.get("max_len", 4)), 1)
    for _ in range(min(max_len, len(mutable_positions))):
        pos = _choice(mutable_positions)
        buf[pos] = _choice(b"abcdefghijklmnopqrstuvwxyz0123456789_")
    return True


def append_tail_block(buf, op, _profile, max_size):
    remaining = max_size - len(buf)
    if remaining <= 0:
        return False
    min_len = max(int(op.get("min_len", 1)), 0)
    max_len = max(int(op.get("max_len", min_len)), min_len)
    max_len = min(max_len, remaining)
    if max_len < min_len:
        return False
    length = random.randrange(min_len, max_len + 1)
    alphabet = op.get("alphabet", "binary")
    if alphabet == "ascii":
        data = bytes(random.randrange(32, 127) for _ in range(length))
    elif alphabet == "zero":
        data = b"\x00" * length
    else:
        data = bytes(random.getrandbits(8) for _ in range(length))
    buf.extend(data)
    return True


def sync_elf32_headers(buf, _op, profile, max_size):
    if not _is_elf32_lsb(buf):
        ensure_elf32_i386(buf, profile, max_size)
    if len(buf) < 52:
        return False

    phoff = _u32(buf, 0x1C)
    shoff = _u32(buf, 0x20)
    phentsize = _u16(buf, 0x2A)
    phnum = _u16(buf, 0x2C)
    shentsize = _u16(buf, 0x2E)
    shnum = _u16(buf, 0x30)
    shstrndx = _u16(buf, 0x32)

    if phoff is None or phoff < 52 or phoff > len(buf):
        phoff = int(profile.get("phoff", 52))
        _w32(buf, 0x1C, phoff, max_size)
    if phentsize != 32:
        phentsize = 32
        _w16(buf, 0x2A, phentsize, max_size)
    if phnum is None or phnum < 0 or phnum > 32 or phoff + phnum * phentsize > len(buf):
        phnum = int(profile.get("phnum", 2))
        _w16(buf, 0x2C, phnum, max_size)

    if shoff is None or shoff < 52 or shoff > len(buf):
        shoff = int(profile.get("shoff", 164))
        _w32(buf, 0x20, shoff, max_size)
    if shentsize != 40:
        shentsize = 40
        _w16(buf, 0x2E, shentsize, max_size)
    if shnum is None or shnum < 0 or shnum > 128 or shoff + shnum * shentsize > len(buf):
        shnum = int(profile.get("shnum", 4))
        _w16(buf, 0x30, shnum, max_size)
    if shstrndx is None or shstrndx >= max(shnum, 1):
        _w16(buf, 0x32, min(int(profile.get("shstrndx", 0)), max(shnum - 1, 0)), max_size)

    for index in range(max(phnum or 0, 0)):
        off = phoff + index * 32
        if off + 32 > len(buf):
            break
        p_offset = _u32(buf, off + 0x04)
        p_filesz = _u32(buf, off + 0x10)
        if p_offset is None or p_offset > len(buf):
            _w32(buf, off + 0x04, min(len(buf), 0x1000), max_size)
            p_offset = _u32(buf, off + 0x04)
        max_filesz = max(len(buf) - (p_offset or 0), 0)
        if p_filesz is None or p_filesz > max_filesz:
            _w32(buf, off + 0x10, max_filesz, max_size)
        p_memsz = _u32(buf, off + 0x14) or 0
        p_filesz = _u32(buf, off + 0x10) or 0
        if p_memsz < p_filesz:
            _w32(buf, off + 0x14, p_filesz, max_size)

    for index in range(max(shnum or 0, 0)):
        off = shoff + index * 40
        if off + 40 > len(buf):
            break
        sh_offset = _u32(buf, off + 0x10)
        sh_size = _u32(buf, off + 0x14)
        if sh_offset is None or sh_offset > len(buf):
            _w32(buf, off + 0x10, len(buf), max_size)
            sh_offset = len(buf)
        max_size_here = max(len(buf) - sh_offset, 0)
        if sh_size is None or sh_size > max_size_here:
            _w32(buf, off + 0x14, max_size_here, max_size)
    return True


def _append_shstrtab_name(buf, name, profile, max_size):
    shstrndx = int(profile.get("shstrndx", 0))
    shoff_val = _u32(buf, 0x20) or 0
    shentsize = _u16(buf, 0x2E) or 40
    shnum = _u16(buf, 0x30) or 0
    if shnum == 0 or shoff_val == 0:
        return None
    strtab_off = _section_header_offset(profile, shstrndx)
    if strtab_off is None or strtab_off + 40 > len(buf):
        return None
    sh_offset = _u32(buf, strtab_off + 0x10)
    sh_size = _u32(buf, strtab_off + 0x14)
    if sh_offset is None or sh_size is None or sh_offset + sh_size > len(buf):
        return None
    name_bytes = name.encode("ascii") + b"\x00"
    insert_at = sh_offset + sh_size - 1
    if insert_at + len(name_bytes) > max_size:
        return None
    if len(buf) < insert_at + len(name_bytes):
        buf.extend(b"\x00" * (insert_at + len(name_bytes) - len(buf)))
    new_name_offset = sh_size - 1
    buf[insert_at:insert_at + len(name_bytes)] = name_bytes
    _w32(buf, strtab_off + 0x14, sh_size + len(name_bytes) - 1, max_size)
    return new_name_offset


def _append_section_header(buf, sh_type, sh_flags, sh_addr, sh_offset,
                           sh_size, sh_link, sh_info, sh_addralign,
                           sh_entsize, profile, max_size):
    shoff = _u32(buf, 0x20) or 0
    shnum = _u16(buf, 0x30) or 0
    shentsize = _u16(buf, 0x2E) or 40
    if shoff == 0:
        return False
    new_shoff = shoff
    shstrndx = _u16(buf, 0x32) or 0
    old_end = shoff + shnum * shentsize
    new_entry = bytearray(shentsize)
    struct.pack_into("<I", new_entry, 0, 0)
    struct.pack_into("<I", new_entry, 4, sh_type)
    struct.pack_into("<I", new_entry, 8, sh_flags)
    struct.pack_into("<I", new_entry, 12, sh_addr)
    struct.pack_into("<I", new_entry, 16, sh_offset)
    struct.pack_into("<I", new_entry, 20, sh_size)
    struct.pack_into("<I", new_entry, 24, sh_link)
    struct.pack_into("<I", new_entry, 28, sh_info)
    struct.pack_into("<I", new_entry, 32, sh_addralign)
    struct.pack_into("<I", new_entry, 36, sh_entsize)
    needed = old_end + shentsize
    if needed > max_size:
        return False
    if len(buf) < needed:
        buf.extend(b"\x00" * (needed - len(buf)))
    buf[old_end:old_end + shentsize] = new_entry
    _w16(buf, 0x30, shnum + 1, max_size)
    if shstrndx >= shnum:
        _w16(buf, 0x32, shnum, max_size)
    return True


def _append_program_header(buf, p_type, p_offset, p_vaddr, p_paddr,
                           p_filesz, p_memsz, p_flags, p_align, max_size):
    phoff = _u32(buf, 0x1C) or 0
    phnum = _u16(buf, 0x2C) or 0
    phentsize = _u16(buf, 0x2A) or 32
    if phoff == 0:
        return False
    old_end = phoff + phnum * phentsize
    new_entry = bytearray(phentsize)
    struct.pack_into("<I", new_entry, 0, p_type)
    struct.pack_into("<I", new_entry, 4, p_offset)
    struct.pack_into("<I", new_entry, 8, p_vaddr)
    struct.pack_into("<I", new_entry, 12, p_paddr)
    struct.pack_into("<I", new_entry, 16, p_filesz)
    struct.pack_into("<I", new_entry, 20, p_memsz)
    struct.pack_into("<I", new_entry, 24, p_flags)
    struct.pack_into("<I", new_entry, 28, p_align)
    needed = old_end + phentsize
    if needed > max_size:
        return False
    if len(buf) < needed:
        buf.extend(b"\x00" * (needed - len(buf)))
    buf[old_end:old_end + phentsize] = new_entry
    _w16(buf, 0x2C, phnum + 1, max_size)
    return True


def construct_note_section(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    names = op.get("names", [".note.ABI-tag", ".note.gnu.build-id", ".note"])
    section_name = _choice(names)
    shnum = _u16(buf, 0x30) or 0
    shoff = _u32(buf, 0x20) or 0
    shentsize = _u16(buf, 0x2E) or 40
    if shnum == 0 or shoff == 0:
        return False
    note_name_off = _append_shstrtab_name(buf, section_name, profile, max_size)
    if note_name_off is None:
        note_name_off = 0
    namesz = 4
    descsz = random.choice([4, 8, 16])
    note_type = random.choice([1, 3, 4, 5])
    note_data_len = 12 + namesz + ((4 - namesz % 4) % 4) + descsz + ((4 - descsz % 4) % 4)
    note_data = bytearray(note_data_len)
    struct.pack_into("<I", note_data, 0, namesz)
    struct.pack_into("<I", note_data, 4, descsz)
    struct.pack_into("<I", note_data, 8, note_type)
    name_padded = b"GNU\x00"
    note_data[12:12 + len(name_padded)] = name_padded
    desc_start = 12 + len(name_padded)
    for i in range(descsz):
        note_data[desc_start + i] = random.getrandbits(8)
    data_offset = len(buf)
    if data_offset + note_data_len > max_size:
        return False
    buf.extend(note_data)
    if not _append_section_header(
        buf, SHT_NOTE, 0x2, 0, data_offset, note_data_len,
        0, 0, 4, 0, profile, max_size
    ):
        buf[data_offset:] = bytearray()
        return False
    return True


def construct_interp_segment(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    interp_paths = op.get("paths", [
        b"/lib/ld-linux.so.2", b"/lib/ld-linux.so.3",
        b"/usr/lib/ld-linux.so.2",
    ])
    interp_bytes = _choice(interp_paths) + b"\x00"
    data_offset = len(buf)
    if data_offset + len(interp_bytes) > max_size:
        return False
    buf.extend(interp_bytes)
    return _append_program_header(
        buf, PT_INTERP, 0, data_offset, data_offset,
        len(interp_bytes), len(interp_bytes), 4, 1, max_size
    )


def construct_gnu_stack_phdr(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    flags = random.choice([0x6, 0x7, 0x5])
    return _append_program_header(
        buf, PT_GNU_STACK, 0, 0, 0,
        0, 0, flags, 0x1000, max_size
    )


def construct_gnu_relro_phdr(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    return _append_program_header(
        buf, PT_GNU_RELRO, 0, 0, 0,
        0, 0, 4, 0x1000, max_size
    )


def construct_dynamic_section(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    section_names = op.get("names", [".dynamic", ".dyn"])
    section_name = _choice(section_names)
    shnum = _u16(buf, 0x30) or 0
    shoff = _u32(buf, 0x20) or 0
    if shnum == 0 or shoff == 0:
        return False
    name_off = _append_shstrtab_name(buf, section_name, profile, max_size)
    if name_off is None:
        name_off = 0
    n_entries = random.randint(2, 4)
    dyn_data = bytearray(n_entries * 8)
    tags = [1, 2, 4, 5, 6, 7, 8, 10, 12, 14, 17]
    for i in range(n_entries):
        tag = random.choice(tags) if i < n_entries - 1 else 0
        val = random.getrandbits(32)
        struct.pack_into("<I", dyn_data, i * 8, tag)
        struct.pack_into("<I", dyn_data, i * 8 + 4, val)
    data_offset = len(buf)
    if data_offset + len(dyn_data) > max_size:
        return False
    buf.extend(dyn_data)
    if not _append_section_header(
        buf, SHT_DYNAMIC, 0x3, 0, data_offset, len(dyn_data),
        0, 0, 4, 8, profile, max_size
    ):
        buf[data_offset:] = bytearray()
        return False
    return True


def construct_relocation_section(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    section_names = op.get("names", [".rel.dyn", ".rel.plt", ".rela.dyn"])
    section_name = _choice(section_names)
    use_rela = section_name.startswith(".rela")
    shnum = _u16(buf, 0x30) or 0
    shoff = _u32(buf, 0x20) or 0
    if shnum == 0 or shoff == 0:
        return False
    name_off = _append_shstrtab_name(buf, section_name, profile, max_size)
    if name_off is None:
        name_off = 0
    n_entries = random.randint(1, 3)
    entry_size = 12 if use_rela else 8
    rel_data = bytearray(n_entries * entry_size)
    reloc_types = [1, 2, 4, 5, 6, 7, 8, 20, 22, 38, 42]
    for i in range(n_entries):
        r_offset = random.getrandbits(32)
        r_info = ((random.randint(0, max(shnum - 1, 0)) << 8) |
                  random.choice(reloc_types))
        struct.pack_into("<I", rel_data, i * entry_size, r_offset)
        if use_rela:
            struct.pack_into("<I", rel_data, i * entry_size + 4, r_info)
            struct.pack_into("<I", rel_data, i * entry_size + 8, random.getrandbits(32))
        else:
            struct.pack_into("<I", rel_data, i * entry_size + 4, r_info)
    data_offset = len(buf)
    if data_offset + len(rel_data) > max_size:
        return False
    buf.extend(rel_data)
    sh_type = SHT_RELA if use_rela else SHT_REL
    if not _append_section_header(
        buf, sh_type, 0x40, 0, data_offset, len(rel_data),
        0, 0, 4, entry_size, profile, max_size
    ):
        buf[data_offset:] = bytearray()
        return False
    return True


def construct_symbol_table_section(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    section_names = op.get("names", [".symtab", ".dynsym"])
    section_name = _choice(section_names)
    shnum = _u16(buf, 0x30) or 0
    shoff = _u32(buf, 0x20) or 0
    if shnum == 0 or shoff == 0:
        return False
    name_off = _append_shstrtab_name(buf, section_name, profile, max_size)
    if name_off is None:
        name_off = 0
    strtab_name = section_name + "_strtab"
    strtab_name_off = _append_shstrtab_name(buf, strtab_name, profile, max_size)
    if strtab_name_off is None:
        strtab_name_off = 0
    strtab_data = bytearray(b"\x00_Data\x00_text\x00_bss\x00_init\x00_fini\x00")
    strtab_offset = len(buf)
    if strtab_offset + len(strtab_data) > max_size:
        return False
    buf.extend(strtab_data)
    n_syms = random.randint(2, 4)
    sym_data = bytearray((n_syms + 1) * 16)
    struct.pack_into("<I", sym_data, 0, 0)
    struct.pack_into("<I", sym_data, 4, 0)
    struct.pack_into("<I", sym_data, 8, 0)
    struct.pack_into("<H", sym_data, 12, 0)
    struct.pack_into("<H", sym_data, 14, 0)
    for i in range(1, n_syms + 1):
        off = i * 16
        st_name_off = random.randint(1, len(strtab_data) - 2)
        st_value = random.getrandbits(32)
        st_size = random.randint(0, 64)
        st_info = random.choice([0x10, 0x11, 0x12, 0x20, 0x22, 0x01, 0x02])
        st_other = 0
        st_shndx = random.randint(0, max(shnum - 1, 0))
        struct.pack_into("<I", sym_data, off, st_name_off)
        struct.pack_into("<I", sym_data, off + 4, st_value)
        struct.pack_into("<I", sym_data, off + 8, st_size)
        struct.pack_into("<B", sym_data, off + 12, st_info)
        struct.pack_into("<B", sym_data, off + 13, st_other)
        struct.pack_into("<H", sym_data, off + 14, st_shndx)
    data_offset = len(buf)
    if data_offset + len(sym_data) > max_size:
        return False
    buf.extend(sym_data)
    sym_shndx = shnum
    if not _append_section_header(
        buf, SHT_SYMTAB, 0x0, 0, data_offset, len(sym_data),
        sym_shndx - 1 if sym_shndx > 0 else 0,
        n_syms + 1, 4, 16, profile, max_size
    ):
        buf[data_offset:] = bytearray()
        return False
    if not _append_section_header(
        buf, SHT_STRTAB, 0x20, 0, strtab_offset, len(strtab_data),
        0, 0, 1, 0, profile, max_size
    ):
        return True
    return True


def construct_hash_table_section(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    section_names = op.get("names", [".hash", ".gnu.hash"])
    section_name = _choice(section_names)
    shnum = _u16(buf, 0x30) or 0
    shoff = _u32(buf, 0x20) or 0
    if shnum == 0 or shoff == 0:
        return False
    name_off = _append_shstrtab_name(buf, section_name, profile, max_size)
    if name_off is None:
        name_off = 0
    nbucket = random.choice([1, 3, 7, 11])
    nchain = random.randint(4, 16)
    hash_data = bytearray((2 + nbucket + nchain) * 4)
    struct.pack_into("<I", hash_data, 0, nbucket)
    struct.pack_into("<I", hash_data, 4, nchain)
    for i in range(nbucket):
        struct.pack_into("<I", hash_data, (2 + i) * 4, random.randint(0, nchain))
    hash_data[(2 + nbucket) * 4:] = b"\x00" * (nchain * 4)
    data_offset = len(buf)
    if data_offset + len(hash_data) > max_size:
        return False
    buf.extend(hash_data)
    if not _append_section_header(
        buf, SHT_HASH, 0x3, 0, data_offset, len(hash_data),
        0, 0, 4, 4, profile, max_size
    ):
        buf[data_offset:] = bytearray()
        return False
    return True


def construct_null_phdr(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    return _append_program_header(
        buf, PT_NULL, 0, 0, 0, 0, 0, 0, 0, max_size
    )


def construct_null_shdr(buf, op, profile, max_size):
    if not _is_elf32_lsb(buf):
        return False
    shoff = _u32(buf, 0x20) or 0
    shnum = _u16(buf, 0x30) or 0
    shentsize = _u16(buf, 0x2E) or 40
    if shoff == 0 or shentsize == 0:
        return False
    old_end = shoff + shnum * shentsize
    needed = old_end + shentsize
    if needed > max_size:
        return False
    if len(buf) < needed:
        buf.extend(b"\x00" * (needed - len(buf)))
    null_entry = bytearray(shentsize)
    buf[old_end:old_end + shentsize] = null_entry
    _w16(buf, 0x30, shnum + 1, max_size)
    return True


OP_HANDLERS = {
    "ensure_elf32_i386": lambda buf, op, profile, max_size: ensure_elf32_i386(buf, profile, max_size),
    "mutate_ehdr_enum": mutate_ehdr_enum,
    "mutate_program_header": mutate_program_header,
    "mutate_section_header": mutate_section_header,
    "mutate_region": mutate_region,
    "mutate_shstrtab": mutate_shstrtab,
    "append_tail_block": append_tail_block,
    "construct_note_section": construct_note_section,
    "construct_interp_segment": construct_interp_segment,
    "construct_gnu_stack_phdr": construct_gnu_stack_phdr,
    "construct_gnu_relro_phdr": construct_gnu_relro_phdr,
    "construct_dynamic_section": construct_dynamic_section,
    "construct_relocation_section": construct_relocation_section,
    "construct_symbol_table_section": construct_symbol_table_section,
    "construct_hash_table_section": construct_hash_table_section,
    "construct_null_phdr": construct_null_phdr,
    "construct_null_shdr": construct_null_shdr,
    "sync_elf32_headers": sync_elf32_headers,
}


def execute_template_plan(data, plan=None, profile=None, max_size=None):
    original = bytes(data or b"")
    try:
        profile = dict(profile or SMALL_EXEC_PROFILE)
        plan = dict(plan or DEFAULT_PLAN)
        max_size = min(int(max_size or _limit(plan, "max_output_size", MAX_OUTPUT_SIZE)), MAX_OUTPUT_SIZE)
        max_ops = min(_limit(plan, "max_ops_per_call", 32), 128)
        buf = bytearray(original[:max_size])
        ops = plan.get("ops", [])
        if not isinstance(ops, list):
            ops = DEFAULT_PLAN["ops"]

        for op in ops[:max_ops]:
            if not isinstance(op, dict):
                continue
            handler = OP_HANDLERS.get(op.get("op"))
            if handler is None:
                continue
            handler(buf, op, profile, max_size)
            if len(buf) > max_size:
                return original
        return bytes(buf)
    except Exception:
        return original


def mutate(data):
    """AFL custom-mutator compatible entry point for quick experiments."""
    return execute_template_plan(data, DEFAULT_PLAN, SMALL_EXEC_PROFILE)


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run an ELF template mutation plan once.")
    parser.add_argument("input", help="input ELF/corpus file")
    parser.add_argument("output", help="output mutated file")
    parser.add_argument("--plan", help="optional JSON plan file")
    parser.add_argument("--seed", type=int, help="optional PRNG seed for reproducible debugging")
    args = parser.parse_args(argv)

    if args.seed is not None:
        random.seed(args.seed)

    with open(args.input, "rb") as f:
        data = f.read()

    plan = _load_json(args.plan) if args.plan else DEFAULT_PLAN
    mutated = execute_template_plan(data, plan, SMALL_EXEC_PROFILE)

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(mutated)

    print(json.dumps({
        "input_size": len(data),
        "output_size": len(mutated),
        "changed": mutated != data,
        "template": plan.get("template", "unknown") if isinstance(plan, dict) else "unknown",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
