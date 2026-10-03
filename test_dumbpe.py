import pytest

import dumbpe
from dumbpe import PeFile
from tempfile import TemporaryFile

def test_pe_header_lfa():

    # I'm not parsing the DOS header again, but just check we are getting the right PE header.

    with open("TEST/lips.exe", 'rb') as f:
        pefile = PeFile.fromfile(f)
        assert pefile.pe_header_lfa == 0x80
        assert pefile.exedata[pefile.pe_header_lfa:pefile.pe_header_lfa+4] == b'PE\x00\x00'

    with open("TEST/tlon.exe", 'rb') as f:
        pefile = PeFile.fromfile(f)
        assert pefile.pe_header_lfa == 0x80
        assert pefile.exedata[pefile.pe_header_lfa:pefile.pe_header_lfa+4] == b'PE\x00\x00'



def test_pe_relocations_addition():
    '''
    Checking we can add new relocations
    '''

    with open("TEST/lips.exe", 'rb') as f:
        pefile = PeFile.fromfile(f)

    orig_relocs = list(pefile.relocations)

    pefile.add_reloc(0x0046CE82)

    assert set(pefile.relocations) == set(orig_relocs + [0x006CE82,])


def test_pe_relocations_save():
    '''
    If we add a relocation, does the new file have the same relocations (in perhaps different order)
    '''

    with open("TEST/lips.exe", 'rb') as f:
        pefile = PeFile.fromfile(f)

    pefile.add_reloc(0x0046CE82)

    with TemporaryFile() as tmpf:
        pefile.tofile(tmpf)

        pefile2 = PeFile.fromfile(tmpf)
        assert set(pefile.relocations) == set(pefile2.relocations)

