# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

## Justin Seitz - justin@immunityinc.com
## Some useful utility functions.

from ctypes import *
try:    
    import win32file
    import win32api
    KERNEL32      = windll.kernel32
except:
    pass

import xml.dom.minidom
import sys


# DEFINES
PAGE_READONLY                 = 0x2
FILE_MAP_READ                 = 0x4
IMAGE_DOS_SIGNATURE           = 0x5a4d
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

BYTE          = c_ubyte
WORD          = c_ushort
DWORD         = c_ulong

MAX_SIZE      = 4096

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ("e_magic", WORD),
        ("e_cblp",  WORD),
        ("e_cp",    WORD),
        ("e_crlc",  WORD),
        ("e_cparhdr", WORD),
        ("e_minalloc",WORD),
        ("e_maxalloc",WORD),
        ("e_ss",    WORD),
        ("e_sp",    WORD),
        ("e_csum",  WORD),
        ("e_ip",    WORD),
        ("e_cs",    WORD),
        ("e_lfarlc",WORD),
        ("e_ovno",  WORD),
        ("e_res",   (WORD*4)),
        ("e_oemid", WORD),
        ("e_oeminfo",WORD),
        ("e_res2",  (WORD*10)),
        ("e_lfanew", DWORD)]

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ("Machine", WORD),
        ("NumberOfSections", WORD),
        ("TimeDateStamp", DWORD),
        ("PointerToSymbolTable", DWORD),
        ("NumberOfSymbols", DWORD),
        ("SizeOfOptionalHeader", WORD),
        ("Characteristics",WORD)
        ]
class DATA_DIRECTORY(Structure):
    _fields_ = [
        ("VirtualAddress", DWORD),
        ("Size", DWORD)
        ]
    
class IMAGE_OPTIONAL_HEADER32(Structure):
    _fields_  = [
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUnitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("BaseOfData", DWORD),
        ("ImageBase", DWORD),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Win32VersionValue", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", DWORD),
        ("SizeOfStackCommit", DWORD),
        ("SizeOfHeapReserve", DWORD),
        ("SizeOfHeapCommit", DWORD),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
        ("DataDirectory", DATA_DIRECTORY)
         ]
    
    
class IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ("Signature", DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER32)
        ]

class MISC(Union):
    _fields_ = [
        ("PhysicalAddress", DWORD),
        ("VirtualSize", DWORD)
        ]
    
class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ("Name", (BYTE*8)),
        ("Misc", MISC),
        ("VirtualAddress", DWORD),
        ("SizeOfRawData", DWORD),
        ("PointerToRawData", DWORD),
        ("PointerToRelocations", DWORD),
        ("PointerToLinenumbers", DWORD),
        ("NumberOfRelocations", WORD),
        ("NumberOfLinenumbers", WORD),
        ("Characteristics", DWORD)
        ]


# 
# Takes the path to an executable and gets the arch
# Params: file_path - path to the executable
#
def get_pe_arch(file_path):
    h_file_map = None
    h_file     = None
    #print "Archivo: " + file_path    
    try:
        arch = "Unknown"
        h_file = KERNEL32.CreateFileW(file_path,win32file.GENERIC_READ, win32file.FILE_SHARE_READ, None, win32file.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, 0)
        
        if h_file != win32file.INVALID_HANDLE_VALUE:
        
            # Create a file mapping
            h_file_map = KERNEL32.CreateFileMappingW( h_file, None, PAGE_READONLY, 0,0,None)
            
            if h_file_map != win32file.INVALID_HANDLE_VALUE:
                # Map the file into memory
                p_base     = c_void_p        
                p_base     = KERNEL32.MapViewOfFile( h_file_map, FILE_MAP_READ, 0,0,0)
                
                # Now we cast the pointer to our IMAGE_DOS_HEADER
                p_dos_header = POINTER(IMAGE_DOS_HEADER)
                dos_header   = cast(p_base, p_dos_header)
                
                # Check to make sure it's a valid PE
                if dos_header.contents.e_magic == IMAGE_DOS_SIGNATURE:     
                    pimage_nt_headers = POINTER(IMAGE_NT_HEADERS)
                    image_nt_header   = cast(p_base + dos_header.contents.e_lfanew, pimage_nt_headers)           

                if image_nt_header.contents.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                    arch = "32 bit executable"
        
                if image_nt_header.contents.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                    arch = "64 bit executable"

                if not KERNEL32.UnmapViewOfFile(p_base):
                    raise Exception( "Can't free memory mapping for %s" % file_path )    
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise
       
    if h_file_map > 0:
        win32api.CloseHandle(h_file_map)
    
    if h_file > 0:
        win32api.CloseHandle(h_file)
    
    return arch



# 
# Takes the path to an executable and parses the .text section out.
# Params: file_path - path to the executable
#
def parse_code_section(file_path):
    try:
        h_file = KERNEL32.CreateFileA(file_path,win32file.GENERIC_READ, win32file.FILE_SHARE_READ, None, win32file.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, 0)
        
        if h_file != win32file.INVALID_HANDLE_VALUE:
            print "Createfile succeeded"
            # Create a file mapping
            h_file_map = KERNEL32.CreateFileMappingA( h_file, None, PAGE_READONLY, 0,0,None)
            
            if h_file_map != win32file.INVALID_HANDLE_VALUE:
                print "CreateFileMappingA succeeded"
                # Map the file into memory
                p_base = c_void_p        
                p_base     = KERNEL32.MapViewOfFile( h_file_map, FILE_MAP_READ, 0,0,0)
                
                # Now we cast the pointer to our IMAGE_DOS_HEADER
                p_dos_header = POINTER(IMAGE_DOS_HEADER)
                dos_header   = cast(p_base, p_dos_header)
                
                # Check to make sure it's a valid PE
                if dos_header.contents.e_magic == IMAGE_DOS_SIGNATURE:
                    print "[*] Valid executable! Continuing."
                
                    pimage_nt_headers = POINTER(IMAGE_NT_HEADERS)
                    image_nt_header   = cast(p_base + dos_header.contents.e_lfanew, pimage_nt_headers)
                      
                    # so that we can cast the proper OPTION_HEADER struct
                    entry_point = image_nt_header.contents.OptionalHeader.AddressOfEntryPoint
                    num_sections= image_nt_header.contents.FileHeader.NumberOfSections
                    
                    
                    count    = 0
                    modifier = 0
                    
                    while count < num_sections:
                        # Get a pointer to the first section header
                        pimage_section_header = POINTER(IMAGE_SECTION_HEADER)
                        image_section_header  = cast(addressof(image_nt_header.contents.OptionalHeader) + image_nt_header.contents.FileHeader.SizeOfOptionalHeader + modifier, pimage_section_header)
                    
                        if image_section_header.contents.VirtualAddress <= entry_point and entry_point < image_section_header.contents.VirtualAddress + image_section_header.contents.Misc.VirtualSize:
                            break
                        
                        modifier += 0x4
                        count    += 1
                    
                    # We now have the appropriate section for .text let's dump the code
                    code_start = p_base + image_section_header.contents.PointerToRawData                
                    code_size  = image_section_header.contents.SizeOfRawData
                    
                    if  code_size < MAX_SIZE:
                        read_size = code_size
                        buffer     = create_string_buffer(code_size)
                    else:
                        read_size = MAX_SIZE
                        buffer     = create_string_buffer(MAX_SIZE)
                                    
                    try:
                        memmove(addressof(buffer), code_start, read_size)
                    except WindowsError:
                        print "Failed memmove operation"
                        pass
                    
                    
                    win32api.CloseHandle( h_file_map )
                    win32api.CloseHandle( h_file )
            
                    # Pretty hex before returning it
                    hexdump = ""
                    for i in buffer:
                        hexdump += "%02x" % ord(i)
                    
                    return hexdump
                
                else:
                    print "Something failed"
                    win32api.CloseHandle(h_file)
                    
    except:
        KERNEL32.OutputDebugStringA("[ElJefeNamedPipe] Failed to parse code section.")
        print "Failed to get file code section: %s" % file_path
        return "Packed or malformed."
            
    return "Packed or malformed."

def xml_to_dict(xml_string):
    doc    = xml.dom.minidom.parseString(xml_string)
    remove_whilespace_nodes(doc.documentElement)
    xml_dict = parse_xml(doc.documentElement)
    
    return xml_dict

#
# Takes the cleaned XML and converts it into a Python dictionary
# Params: parent - the XML document.
#
def parse_xml(parent):        
        child = parent.firstChild
        if (not child):
                return None
        elif (child.nodeType == xml.dom.minidom.Node.TEXT_NODE):
                return child.nodeValue

        d={}
        while child is not None:
                if (child.nodeType == xml.dom.minidom.Node.ELEMENT_NODE):
                        try:
                                d[child.tagName]
                        except KeyError:
                                d[child.tagName]=[]
                        d[child.tagName].append(parse_xml(child))
                child = child.nextSibling
        return d

#
# Removes whitespace or blank nodes from the XML tree
# Params: node - the XML node to be cleaned, can pass root XML element
#
def remove_whilespace_nodes(node, unlink=True):
        remove_list = []
        for child in node.childNodes:
                if child.nodeType == xml.dom.Node.TEXT_NODE and not child.data.strip():
                        remove_list.append(child)
                elif child.hasChildNodes():
                        remove_whilespace_nodes(child, unlink)
        for node in remove_list:
                node.parentNode.removeChild(node)
                if unlink:
                        node.unlink()
