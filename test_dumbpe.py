import pytest

import dumbpe
from dumbpe import PeFile


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
