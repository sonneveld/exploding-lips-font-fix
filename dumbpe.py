
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Self


IMAGE_DOS_SIGNATURE = 0x5A4D # MZ
IMAGE_NT_SIGNATURE = 0x00004550 # PE

def is_power_of_two(n):
    return (n != 0) and (n & (n-1) == 0)


'''
The PE Header can be located from the e_lfanew offset located in the MZ DOS header.
'''

# characteristics
IMAGE_FILE_RELOCS_STRIPPED         = 0x0001 # Relocation info stripped from file.
IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002 # File is executable  (i.e. no unresolved externel references).
IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004 # [DEPRECATED] Line nunbers stripped from file.
IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008 # [DEPRECATED] Local symbols stripped from file.
IMAGE_FILE_AGGRESIVE_WS_TRIM       = 0x0010 # [DEPRECATED] Agressively trim working set
IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020 # Application can handle > 2-GB addresses.
IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080 # [DEPRECATED] Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. 
IMAGE_FILE_32BIT_MACHINE           = 0x0100 # 32 bit word machine.
IMAGE_FILE_DEBUG_STRIPPED          = 0x0200 # Debugging info stripped from file in .DBG file
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400 # If Image is on removable media, copy and run from the swap file.
IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800 # If Image is on Net, copy and run from the swap file.
IMAGE_FILE_SYSTEM                  = 0x1000 # System File.
IMAGE_FILE_DLL                     = 0x2000 # File is a DLL.
IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000 # File should only be run on a UP machine
IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000 # [DEPRECATED] Big endian: the MSB precedes the LSB in memory.

# machine type
IMAGE_FILE_MACHINE_UNKNOWN  = 0
IMAGE_FILE_MACHINE_I386     = 0x14c     # Intel 386.
IMAGE_FILE_MACHINE_AMD64    = 0x8664    # x64

PEHEADER_STRUCT = struct.Struct("<IHHIIIHH")

@dataclass
class PeHeader:
    mMagic : int                    # REQUIRED
    mMachine : int                  # REQUIRED
    mNumberOfSections : int         # REQUIRED
    mTimeDateStamp : int
    mPointerToSymbolTable : int
    mNumberOfSymbols : int
    mSizeOfOptionalHeader : int     # REQUIRED
    mCharacteristics : int          # REQUIRED

    @classmethod
    def from_buffer(cls, buffer, offset) -> Self:
        values = PEHEADER_STRUCT.unpack_from(buffer, offset)
        result = cls(*values)
        assert result.mMagic == IMAGE_NT_SIGNATURE   # PE
        assert result.mMachine == IMAGE_FILE_MACHINE_I386
        return result

    @classmethod
    def size(cls) -> int:
        return PEHEADER_STRUCT.size

    def to_buffer(self, buffer, offset):
        values = [
            self.mMagic,
            self.mMachine,
            self.mNumberOfSections,
            self.mTimeDateStamp,
            self.mPointerToSymbolTable,
            self.mNumberOfSymbols,
            self.mSizeOfOptionalHeader,
            self.mCharacteristics,
        ]
        PEHEADER_STRUCT.pack_into(buffer, offset, *values)



'''
PE Optional Headers
Which is probably not optional really. It is located immediately after the PE Header.
'''

IMAGE_DIRECTORY_ENTRY_EXPORT       =  0 # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT       =  1 # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE     =  2 # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION    =  3 # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY     =  4 # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC    =  5 # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG        =  6 # Debug Directory
IMAGE_DIRECTORY_ENTRY_COPYRIGHT    =  7 # Description String
IMAGE_DIRECTORY_ENTRY_GLOBALPTR    =  8 # Machine Value (MIPS GP)
IMAGE_DIRECTORY_ENTRY_TLS          =  9 # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  = 10 # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11 # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT          = 12 # Import Address Table


PE32OPTDIR_STRUCT = struct.Struct("<II")

@dataclass
class Pe32ImageDataDirectory:
    VirtualAddress : int
    Size : int

    @classmethod
    def from_buffer(cls, buffer, offset) -> Self:
        values = PE32OPTDIR_STRUCT.unpack_from(buffer, offset)
        return cls(*values)

    @classmethod
    def size(cls) -> int:
        return PE32OPTDIR_STRUCT.size


IMAGE_NT_OPTIONAL_HDR_PE32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR_PE32_PLUS_MAGIC = 0x20b



IMAGE_SUBSYSTEM_UNKNOWN     = 0 # Unknown subsystem.
IMAGE_SUBSYSTEM_NATIVE      = 1 # Image doesn't require a subsystem.
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2 # Image runs in the Windows GUI subsystem.
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3 # Image runs in the Windows character subsystem.


PE32OPTHEAD_STRUCT = struct.Struct("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII")

@dataclass
class Pe32OptionalHeader:
    # standard:
    mMagic : int                        # REQUIRED
    mMajorLinkerVersion : int
    mMinorLinkerVersion : int
    mSizeOfCode : int
    mSizeOfInitializedData : int
    mSizeOfUninitializedData : int
    mAddressOfEntryPoint : int          # REQUIRED
    mBaseOfCode : int
    mBaseOfData : int
    # windows specific:
    mImageBase : int                    # REQUIRED
    mSectionAlignment : int             # REQUIRED
    mFileAlignment : int                # REQUIRED
    mMajorOperatingSystemVersion : int
    mMinorOperatingSystemVersion : int
    mMajorImageVersion : int
    mMinorImageVersion : int
    mMajorSubsystemVersion : int        # REQUIRED
    mMinorSubsystemVersion : int
    mWin32VersionValue : int
    mSizeOfImage : int                  # REQUIRED
    mSizeOfHeaders : int                # REQUIRED
    mCheckSum : int
    mSubsystem : int                    # REQUIRED
    mDllCharacteristics : int
    mSizeOfStackReserve : int
    mSizeOfStackCommit : int
    mSizeOfHeapReserve : int
    mSizeOfHeapCommit : int
    mLoaderFlags : int
    mNumberOfRvaAndSizes : int          # REQUIRED
    dirValues : list[Pe32ImageDataDirectory] = field(default_factory=list)

    @classmethod
    def from_buffer(cls, buffer, offset) -> Self:
        values = PE32OPTHEAD_STRUCT.unpack_from(buffer, offset)
        result = cls(*values)

        assert result.mMagic == IMAGE_NT_OPTIONAL_HDR_PE32_MAGIC    # PE32
        assert result.mImageBase % (64*1024) == 0
        assert result.mImageBase == 0x400000
        assert result.mSectionAlignment >= result.mFileAlignment
        assert is_power_of_two(result.mFileAlignment)
        assert result.mFileAlignment >= 512
        assert result.mFileAlignment <= (64*1024)
        assert result.mWin32VersionValue == 0
        assert result.mSizeOfImage % result.mSectionAlignment == 0 
        assert result.mSizeOfHeaders % result.mFileAlignment == 0 
        assert result.mSubsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI
        assert result.mLoaderFlags == 0

        offset += PE32OPTHEAD_STRUCT.size
        assert result.mNumberOfRvaAndSizes == 16
        for _ in range(result.mNumberOfRvaAndSizes):
            dirvalue = Pe32ImageDataDirectory.from_buffer(buffer, offset)
            offset += Pe32ImageDataDirectory.size()
            result.dirValues.append(dirvalue)
        # Imports is required.. check
        assert result.dirValues[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0
        return result

    def to_buffer(self, buffer:bytes|bytearray, offset:int):
        values = [
            self.mMagic,
            self.mMajorLinkerVersion,
            self.mMinorLinkerVersion,
            self.mSizeOfCode,
            self.mSizeOfInitializedData,
            self.mSizeOfUninitializedData,
            self.mAddressOfEntryPoint,
            self.mBaseOfCode,
            self.mBaseOfData,
            self.mImageBase,
            self.mSectionAlignment,
            self.mFileAlignment,
            self.mMajorOperatingSystemVersion,
            self.mMinorOperatingSystemVersion,
            self.mMajorImageVersion,
            self.mMinorImageVersion,
            self.mMajorSubsystemVersion,
            self.mMinorSubsystemVersion,
            self.mWin32VersionValue,
            self.mSizeOfImage,
            self.mSizeOfHeaders,
            self.mCheckSum,
            self.mSubsystem,
            self.mDllCharacteristics,
            self.mSizeOfStackReserve,
            self.mSizeOfStackCommit,
            self.mSizeOfHeapReserve,
            self.mSizeOfHeapCommit,
            self.mLoaderFlags,
            self.mNumberOfRvaAndSizes,
        ]
        PE32OPTHEAD_STRUCT.pack_into(buffer, offset, *values)


'''
Section Headers.

Define all the data that gets loaded into the process memory. Immediately after the
optional header by following the optioanl header size.
'''

IMAGE_SCN_CNT_CODE = 0x00000020 # The section contains executable code.
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040 # The section contains initialized data.
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080 # The section contains uninitialized data.

IMAGE_SCN_MEM_DISCARDABLE = 0x02000000 # The section can be discarded as needed.
IMAGE_SCN_MEM_EXECUTE = 0x20000000 # The section can be executed as code.
IMAGE_SCN_MEM_READ = 0x40000000 # The section can be read.
IMAGE_SCN_MEM_WRITE = 0x80000000 # The section can be written to.

SECTHEAD_STRUCT = struct.Struct("<8sIIIIIIHHI")

@dataclass
class SectionHeader:
    mName : bytes
    mVirtualSize : int          # REQUIRED
    mVirtualAddress : int       # REQUIRED
    mSizeOfRawData : int        # REQUIRED
    mPointerToRawData : int     # REQUIRED
    mPointerToRelocations : int
    mPointerToLinenumbers : int
    mNumberOfRelocations : int
    mNumberOfLinenumbers : int
    mCharacteristics : int      # REQUIRED

    @classmethod
    def from_buffer(cls, buffer:bytes|bytearray, offset:int, pe32_opt_header:Pe32OptionalHeader) -> Self:
        values = SECTHEAD_STRUCT.unpack_from(buffer, offset)
        result = cls(*values)
        # mVirtualSize is not required to be rounded
        # "Because the SizeOfRawData field is rounded but the VirtualSize field is not, it is possible for SizeOfRawData to be greater than VirtualSize as well."
        # Also it is quite often 0 (in older executables)! So forget about it.
        # assert result.mVirtualSize % pe32_opt_header.mSectionAlignment == 0  # I don't think this one is required
        assert result.mVirtualAddress % pe32_opt_header.mSectionAlignment == 0
        assert result.mSizeOfRawData % pe32_opt_header.mFileAlignment == 0
        assert result.mPointerToRawData % pe32_opt_header.mFileAlignment == 0
        return result

    @classmethod
    def size(cls) -> int:
        return SECTHEAD_STRUCT.size

    def into_buffer(self, buffer:bytes|bytearray, offset:int):
        values = [
            self.mName,
            self.mVirtualSize,
            self.mVirtualAddress,
            self.mSizeOfRawData,
            self.mPointerToRawData,
            self.mPointerToRelocations,
            self.mPointerToLinenumbers,
            self.mNumberOfRelocations,
            self.mNumberOfLinenumbers,
            self.mCharacteristics,
        ]
        SECTHEAD_STRUCT.pack_into(buffer, offset, *values)


def parse_relocations(buffer, offset):

    while True:
        # print("-")
        VirtualAddress, SizeOfBlock = struct.unpack_from("<II", buffer, offset)
        # print(hex(VirtualAddress), hex(SizeOfBlock))
        nextblock_offset = offset+SizeOfBlock
        offset += 8

        if VirtualAddress == 0:
            break

        SizeOfBlock -= 8
        while SizeOfBlock:
            entry_b, = struct.unpack_from("<H", buffer, offset)
            offset += 2
            SizeOfBlock -= 2
            entry_type = (entry_b >> 12) & 0xF
            entry_offset = entry_b & 0xFFF
            # if entry_type == 0:
                # print(entry_offset)
            if entry_type != 0:
                assert entry_type == 3
                yield VirtualAddress + entry_offset
                # print('et', entry_type)
            # print(' ', hex(entry_offset), '->', hex(VirtualAddress + entry_offset), entry_type)

        assert offset == nextblock_offset
        offset = nextblock_offset
        


def encode_relocations(relocations):

    result = bytearray()

    pages = defaultdict(list)

    for address in relocations:
        page_idx, page_offset = divmod(address, 0x1000)
        page_address = page_idx*0x1000
        pages[page_address].append(page_offset)


    for page_address in sorted(pages.keys()):

        assert len(result) % 4 == 0

        offsets = pages[page_address]
        block_sz = 4 + 4 + 2*len(offsets)
        padding_sz = 0
        _,remaining = divmod(block_sz, 4)
        if remaining != 0:
            padding_sz += 4-remaining

        result.extend( struct.pack("<II",page_address, block_sz+padding_sz) )
        for offset in offsets:
            value = (3 << 12) | offset
            result.extend( struct.pack("<H", value))
        result.extend(b'\x00'*padding_sz)

    # result.extend(b'\x00' * (wanted_size-len(result)))
    # assert len(result) == wanted_size

    return result 





@dataclass
class PeFile:

    exedata: bytearray
    pe_header_lfa : int
    pe_header: PeHeader
    pe32_opt_header_lfa: int
    pe32_opt_header: Pe32OptionalHeader
    sections_lfa : int
    sections: list[SectionHeader]
    reloc_s: SectionHeader
    relocations: list[int]


    @classmethod
    def fromfile(cls, f) -> Self:
        f.seek(0)
        data = f.read()
        exedata = bytearray(data)

        # DOS stub
        mz_magic,  = struct.unpack_from('<H', exedata, 0)
        assert mz_magic == IMAGE_DOS_SIGNATURE # MZ
        e_lfanew,  = struct.unpack_from('<I', exedata, 0x3C)
        # print(hex(e_lfanew))

        lfa = e_lfanew

        pe_header_lfa = lfa
        pe_header = PeHeader.from_buffer(exedata, lfa)
        lfa += PeHeader.size()
        # print(pe_header)

        pe32_opt_header_lfa = lfa
        pe32_opt_header = Pe32OptionalHeader.from_buffer(exedata, lfa)
        lfa += pe_header.mSizeOfOptionalHeader
        # print(pe32_opt_header)

        sections_lfa = lfa
        reloc_s = None
        sections = []
        for i in range(pe_header.mNumberOfSections):
            s = SectionHeader.from_buffer(exedata, lfa, pe32_opt_header)
            lfa += SectionHeader.size()
            if s.mName == b'.reloc\x00\x00':
                reloc_s = s
            sections.append(s)
        assert reloc_s is not None

        relocations = list(parse_relocations(exedata, reloc_s.mPointerToRawData))

        return cls(exedata, pe_header_lfa, pe_header, pe32_opt_header_lfa, pe32_opt_header, sections_lfa, sections, reloc_s, relocations)

    def tofile(self, f):
        self.update_reloc()
        f.write(self.exedata)


    def update_reloc(self):
        new_relocations_b = encode_relocations(self.relocations)
        assert len(new_relocations_b) <= self.reloc_s.mSizeOfRawData

        # clear it first
        self.exedata[self.reloc_s.mPointerToRawData:self.reloc_s.mPointerToRawData+self.reloc_s.mSizeOfRawData] = b'\x00'*self.reloc_s.mSizeOfRawData

        self.exedata[self.reloc_s.mPointerToRawData:self.reloc_s.mPointerToRawData+len(new_relocations_b)] = new_relocations_b

        reloc_dir_size_offset = self.pe32_opt_header_lfa + PE32OPTHEAD_STRUCT.size + PE32OPTDIR_STRUCT.size*IMAGE_DIRECTORY_ENTRY_BASERELOC

        struct.pack_into("<I", self.exedata, reloc_dir_size_offset+4, len(new_relocations_b))


    def clear_relocs(self, start_offset, end_offset):

        assert start_offset >= self.pe32_opt_header.mImageBase
        assert end_offset >= self.pe32_opt_header.mImageBase
        start_offset -= self.pe32_opt_header.mImageBase
        end_offset -= self.pe32_opt_header.mImageBase

        to_remove = range(start_offset, end_offset)
        l = len(self.relocations)
        self.relocations = [x for x in self.relocations if x not in to_remove]
        l2 = len(self.relocations)

        print(f'removed {l-l2} relocations')


    def add_reloc(self, offset):
        assert offset >= self.pe32_opt_header.mImageBase
        offset -= self.pe32_opt_header.mImageBase

        l = len(self.relocations)

        if offset not in self.relocations:
            self.relocations.append(offset)
        else:
            print(f"offset {offset} already in .reloc")
        l2 = len(self.relocations)

        print(f'added {l2-l} relocations')


    def get_section_virtual_size(self, section:SectionHeader):
        '''
        Not all sections get a virtual size defined. Windows probably doesn't care?

        Anyway, we can figure it out by either 
        1) rounding up the raw size to nearest section alignment 
        or
        2) look at the difference from the section virtual adress and the next one.

        There's some details about it here: https://wiki.osdev.org/PE#Section_header
        '''

        assert section in self.sections

        # Already defined in header, return it.
        if section.mVirtualSize > 0:
            return section.mVirtualSize

        # guess based on raw data size.
        virtual_size = section.mSizeOfRawData
        remaining = section.mSizeOfRawData % self.pe32_opt_header.mSectionAlignment
        if remaining > 0:
            virtual_size += self.pe32_opt_header.mSectionAlignment - remaining
        assert virtual_size % self.pe32_opt_header.mSectionAlignment == 0

        # don't think the sections are guaranteed sorted.
        sections_sorted = sorted(self.sections, key=lambda x:(x.mVirtualAddress, x.mVirtualSize))

        # trim it down if the next section overlaps I guess.
        section_i = sections_sorted.index(section)
        section_j = section_i+1
        if section_j < len(sections_sorted):
            section_next = sections_sorted[section_j]
            virtual_gap = section_next.mVirtualAddress - section.mVirtualAddress
            virtual_size = min(virtual_size, virtual_gap)

        return virtual_size


    def update_sections(self):

        # i'm assuming section data is immediately after section headers. so 
        # make sure we don't overwrite it.
        sections_bytes_len = len(self.sections) * SectionHeader.size()
        sections_end_offset = min(s.mPointerToRawData for s in self.sections if s.mPointerToRawData > 0)
        assert self.sections_lfa + sections_bytes_len <= sections_end_offset 

        offset = self.sections_lfa
        for s in self.sections:
            s.into_buffer(self.exedata, offset)
            offset += SectionHeader.size()

        # and update pe header.
        self.pe_header.mNumberOfSections = len(self.sections)
        self.pe_header.to_buffer(self.exedata, self.pe_header_lfa)

        # and size of raw data
        size_of_init_data = 0
        for s in self.sections:
            if (s.mCharacteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == 0:
                continue
            if not (s.mName.startswith(b'.idata') or s.mName.startswith(b'DGROUP')):
                continue
            size_of_init_data += s.mSizeOfRawData
        self.pe32_opt_header.mSizeOfInitializedData = size_of_init_data

        self.pe32_opt_header.mSizeOfImage = max(s.mVirtualAddress + self.get_section_virtual_size(s) for s in self.sections)

        self.pe32_opt_header.to_buffer(self.exedata, self.pe32_opt_header_lfa)


    def add_section(self, name_s:str, mCharacteristics:int, sectdata:bytes|bytearray):

        name_b = name_s.encode('ascii')
        name_b += b'\x00'*(8-len(name_b))

        # add padding to end of exe before we add new section data just in case.
        assert self.pe32_opt_header.mFileAlignment > 0
        remaining = len(self.exedata) % self.pe32_opt_header.mFileAlignment
        if remaining > 0:
            self.exedata.extend(b'\x00' * (self.pe32_opt_header.mFileAlignment - remaining))
        remaining = len(self.exedata) % self.pe32_opt_header.mFileAlignment
        assert remaining == 0 

        # ensure section data is multiple of filealignment
        remaining = len(sectdata) % self.pe32_opt_header.mFileAlignment
        if remaining > 0:
            sectdata = sectdata + b'\x00' * (self.pe32_opt_header.mFileAlignment - remaining)
        remaining = len(sectdata) % self.pe32_opt_header.mFileAlignment
        assert remaining == 0 

        mSizeOfRawData = len(sectdata)
        mPointerToRawData = len(self.exedata)

        # add to executable
        self.exedata.extend(sectdata)

        # virtually position new section immediately after everything else.
        mVirtualSize = 0
        mVirtualAddress = max( s.mVirtualAddress + self.get_section_virtual_size(s) for s in self.sections )

        new_section = SectionHeader(name_b, mVirtualSize, mVirtualAddress, mSizeOfRawData, mPointerToRawData, 0, 0, 0, 0, mCharacteristics)

        self.sections.append(new_section)

        self.update_sections()

        return new_section


    def lfa_from_vaddr(self, vaddr):
        '''
        get a file offset for a virtual address, i.e. one you might get in ida pro
        '''
        for s in self.sections:
            vaddr_start = self.pe32_opt_header.mImageBase + s.mVirtualAddress
            vaddr_end = vaddr_start + self.get_section_virtual_size(s)
            if vaddr in range(vaddr_start, vaddr_end):
                raw_offset = vaddr - vaddr_start
                assert raw_offset >= 0
                assert raw_offset < s.mSizeOfRawData
                return s.mPointerToRawData + raw_offset
        raise ValueError(f"Could not resolve logical file address from virtual address 0x{vaddr:08x}")


if __name__ == "__main__":

    with open("GAME/lips.exe", 'rb') as f:
        pefile = PeFile.fromfile(f)

    # x = 0
    # x = 0xe20000e0
    # for s in pefile.sections:
    #     x |= s.mCharacteristics
    # print(hex(x))



    # x = 0x182
    # x |= pefile.pe_header.mCharacteristics

    # y = 1
    # for _ in range(32):
    #     if y & x:
    #         print(hex(y))
    #     y <<= 1
            

    # with open("testout.exe", "wb") as f:
    #     pefile.tofile(f)

    # mz_magic,  = struct.unpack_from('<H', exedata, 0)
    # assert mz_magic == 0x5A4D # MZ

    # e_lfanew,  = struct.unpack_from('<I', exedata, 0x3C)
    # print(hex(e_lfanew))


    # offset = e_lfanew

    # # pe_magic, = struct.unpack_from("<I", exedata, e_lfanew)
    # # assert pe_magic == 0x4550   # PE

    # pe_header = PeHeader.from_buffer(exedata, offset)
    # # pe_header = struct.unpack_from("<IHHIIIHH", exedata, e_lfanew)
    # print(pe_header)


    # offset += PeHeader.size()

    # pe32_opt_header = Pe32OptionalHeader.from_buffer(exedata, offset)
    # print(pe32_opt_header)

    # offset += pe_header.mSizeOfOptionalHeader

    # # print(exedata[offset:offset+10])
    # print()


    # reloc_s : SectionHeader|None = None

    # for i in range(pe_header.mNumberOfSections):

    #     s = SectionHeader.from_buffer(exedata, offset)
    #     offset += SectionHeader.size()

    #     print(s)
    #     if s.mName == b'.reloc\x00\x00':
    #         reloc_s = s

    # assert reloc_s is not None
    # print()
    # print(reloc_s)


    # relocations = list(parse_relocations(exedata, reloc_s.mPointerToRawData))

    # orig_relocation_bin = exedata[reloc_s.mPointerToRawData:reloc_s.mPointerToRawData+reloc_s.mSizeOfRawData]

    # # print(relocations[:100])
    # # print(len(set(relocations)))
    # # reloc_bin = exedata[reloc_s.mPointerToRawData: reloc_s.mPointerToRawData+reloc_s.mSizeOfRawData]
    # # print(reloc_bin[:100])

    # new_relocations_bin = encode_relocations(relocations, reloc_s.mSizeOfRawData)


    # print(len(orig_relocation_bin))
    # print(len(new_relocations_bin))

    # relocations2 = list(parse_relocations(new_relocations_bin, 0))


    # print(relocations == relocations2)


    # # print(orig_relocation_bin[:-100])

    # with open('reloc-orig.bin', 'wb') as f:
    #     f.write(orig_relocation_bin)
    # with open('reloc-new.bin', 'wb') as f:
    #     f.write(new_relocations_bin)



    # # for o in relocations:
    # #     if o not in relocations2:
    # #         print(hex(o))


    # # so we need to try to fit in within the reloc siz.e. but also update the reloc directry entry


