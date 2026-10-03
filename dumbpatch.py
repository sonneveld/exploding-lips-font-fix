
import datetime
import os
import os.path
import struct
import subprocess
import sys

from blake3 import blake3

import dumbpe

NASM_PATH='c:/apps/nasm/nasm-2.16.03/nasm.exe'


CODE_FILE_POS = 0x400
CODE = 0x00401000
CODE_END = 0x0050C400

DGROUP_FILE_POS = 0x10d800
DGROUP = 0x0050F000
DGROUP_END = 0x0052B000

EXE_PATH="GAME/lips.exe"

# DON'T CALL IT PATCHED. WINDOWS WANTS TO RUN IT AS ADMIN
OUT_PATCHED_PATH="GAME/lips-fixed.exe"


def hashit(fpath):
    hasher = blake3()
    with open(fpath, 'rb') as f:
        d = f.read()
    hasher.update(d)
    return hasher.hexdigest()

def fill(buffer:bytearray, offset:int, fillen:int, b:bytes):
    assert len(b) == 1
    while fillen > 0:
        buffer[offset] = b[0]
        offset += 1
        fillen -= 1

def setbuf(buffer:bytearray, offset:int, b_ins:bytes):
    buffer[offset:offset+len(b_ins)] = b_ins


def nasm(asmfile):
    basename, _ = os.path.splitext(asmfile)
    binpath = basename + ".bin"
    subprocess.run([NASM_PATH, asmfile, '-o', binpath], check=True)
    with open(binpath, 'rb') as f:
        asmbin = f.read()
    return asmbin



def set_code(pefile, coffset, cbuf, relocs=None):
    if relocs is None:
        relocs = []

    exedata = pefile.exedata

    # clear with nops, remove relocs
    fill(exedata, pefile.lfa_from_vaddr(coffset), len(cbuf), b'\x90')
    pefile.clear_relocs(coffset, coffset+len(cbuf))

    setbuf(exedata, pefile.lfa_from_vaddr(coffset), cbuf)

    for r in relocs:
        pefile.add_reloc(coffset + r)


    
def patchit(OUT_PATH):

    print()
    print(f"Patching {EXE_PATH}...")

    # we use current date in a couple of places
    # now = datetime.datetime.now()

    # sanity check that we're patching the write file.
    assert hashit(EXE_PATH) == "e432f8459f8f8dca32e6c1f82edec661bdc131a5720e2d4e7dbfde64f8aa6626"

    with open(EXE_PATH, 'rb') as f:
        pefile = dumbpe.PeFile.fromfile(f)
        

    # load assembled code
    # patch0bin = nasm('patch0.asm')


    with open("IBM_VGA_8x8.bin", 'rb') as f:
        fontdata = f.read()

    sect_characteristics = dumbpe.IMAGE_SCN_CNT_INITIALIZED_DATA | dumbpe.IMAGE_SCN_MEM_READ
    assert sect_characteristics == 0x40000040
    fontsect = pefile.add_section("DGROUP2", sect_characteristics, fontdata)


    '''
    These are the refernces to '0F FA 6E' which is the pointer to the vga bios character data

    Address	Function	Instruction
    AUTO:0046CE82	sub_46CE0F	add     eax, 0FFA6Eh
    AUTO:004755A1	sub_47550A	add     eax, 0FFA6Eh
    AUTO:00475B1D	s_draw_char_475AB1	add     eax, 0FFA6Eh
    AUTO:00475DE8	sub_475D7F	add     eax, 0FFA6Eh
    AUTO:00475F43	sub_475EDA	add     eax, 0FFA6Eh
    '''


    font_offsets = [
        0x0046CE82,
        0x004755A1,
        0x00475B1D,
        0x00475DE8,
        0x00475F43,
    ]

    new_offset_b = struct.pack("<I", pefile.pe32_opt_header.mImageBase + fontsect.mVirtualAddress)
    for coffset in font_offsets:
        set_code(pefile, coffset, new_offset_b, [0,])


    with open(OUT_PATH, 'wb')  as f:
        pefile.tofile(f)
        # f.write(exedata)
    
    print(f"Wrote {OUT_PATH}")





if __name__ == "__main__":
    patchit(OUT_PATCHED_PATH)
