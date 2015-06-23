"""
This code was adapted from the code on
	http://forum.sysinternals.com/howto-verify-the-digital-signature-of-a-file_topic19247.html
"""

import ctypes
from ctypes import POINTER
from ctypes.wintypes import *
import sys

PVOID = ctypes.c_void_p
NULL = 0
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
WTD_UI_ALL = 1
WTD_UI_NONE = 2
WTD_UI_NOBAD = 3
WTD_UI_NOGOOD = 4

WTD_REVOKE_NONE = 0x00000000
WTD_REVOKE_WHOLECHAIN = 0x00000001

WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_CHOICE_BLOB = 3
WTD_CHOICE_SIGNER = 4
WTD_CHOICE_CERT = 5

WTD_STATEACTION_IGNORE = 0x00000000
WTD_STATEACTION_VERIFY = 0x00000001
WTD_STATEACTION_CLOSE = 0x00000002
WTD_STATEACTION_AUTO_CACHE = 0x00000003
WTD_STATEACTION_AUTO_CACHE_FLUSH  = 0x00000004
WTD_UICONTEXT_EXECUTE = 0

class GUID(ctypes.Structure):
	_fields_ = [
		('Data1', DWORD),
		('Data2', WORD), # LPCWSTR == constant WCHAR
		('Data3', WORD),
		('Data4', BYTE * 8),
	]
	
class WINTRUST_FILE_INFO(ctypes.Structure):
	_fields_ = [
		('cbStruct', DWORD),
		('pcwszFilePath', WCHAR), # LPCWSTR == constant WCHAR
		('hFile', HANDLE),
		('pgKnownSubject', POINTER(GUID)),
	]
	
class WINTRUST_CATALOG_INFO(ctypes.Structure):
	_fields_ = [
		('cbStruct', DWORD),
		('dwCatalogVersion', DWORD),
		('pcwszCatalogFilePath', LPCWSTR),
		('pcwszMemberTag',LPCWSTR),
		('pcwszMemberFilePath', LPCWSTR),
		('hMemberFile', HANDLE),
		('pbCalculatedFileHash', POINTER(BYTE)),
		('cbCalculatedFileHash', DWORD),
		('pcCatalogContext', DWORD), # POINTER(CTL_CONTEXT)
	]
	
	
# Incomplete structure, i'm just defining what i'm using		
class union_WINTRUST_DATA(ctypes.Union):
	__slots__ = [
    'pFile',
    'pCatalog',
	]
	_fields_ = [
    ('pFile', POINTER(WINTRUST_FILE_INFO)),
    ('pCatalog', DWORD),
	]		
	
class CATALOG_INFO(ctypes.Structure):
	_fields_ = [
		('cbStruct', DWORD),
		('wszCatalogFile', WCHAR * 260),
	]

class WINTRUST_DATA(ctypes.Structure):
	_anonymous_ = ("union",)
	_fields_ = [
		('cbStruct', DWORD),
		('pPolicyCallbackData', LPVOID),
		('pSIPClientData', LPVOID),
		('dwUIChoice',DWORD),
		('fdwRevocationChecks', DWORD),
		('dwUnionChoice', DWORD),
		('union',union_WINTRUST_DATA),
		('dwStateAction', DWORD),
		('hWVTStateData', HANDLE),
		('pwszURLReference', POINTER(WCHAR)),
		('dwProvFlags', DWORD),
		('dwUIContext', DWORD),
	]
	
def is_file_signed(FilePath):
	Context = PVOID()
	HashSize = DWORD(0)
	GetLastError = ctypes.windll.KERNEL32.GetLastError
	GetLastError.restype = ctypes.wintypes.DWORD
	
	CryptCATAdminEnumCatalogFromHash =  ctypes.windll.wintrust.CryptCATAdminEnumCatalogFromHash
	CryptCATAdminReleaseCatalogContext = ctypes.windll.wintrust.CryptCATAdminReleaseCatalogContext
	CryptCATCatalogInfoFromContext = ctypes.windll.wintrust.CryptCATCatalogInfoFromContext
	
	WinVerifyTrust = ctypes.windll.wintrust.WinVerifyTrust
	WinVerifyTrust.argtypes = (
		DWORD,
		POINTER(GUID),
		LPVOID
	)
	WinVerifyTrust.restype = LONG
	
	CryptCATAdminAcquireContext	= ctypes.windll.wintrust.CryptCATAdminAcquireContext
	CryptCATAdminReleaseContext = ctypes.windll.wintrust.CryptCATAdminReleaseContext
	
	CryptCATAdminCalcHashFromFileHandle = ctypes.windll.wintrust.CryptCATAdminCalcHashFromFileHandle
	CryptCATAdminCalcHashFromFileHandle.restype = BOOL
	CryptCATAdminCalcHashFromFileHandle.argtypes = (
		HANDLE,
		POINTER(DWORD),
		ctypes.c_void_p,
		DWORD,
	)
	CreateFileW = ctypes.windll.kernel32.CreateFileW
	CreateFileW.restype = ctypes.wintypes.HANDLE
	CreateFileW.argtypes = (
		ctypes.wintypes.LPCWSTR, # lpFileName
		ctypes.wintypes.DWORD, # dwDesiredAccess
		ctypes.wintypes.DWORD, # dwShareMode
		LPVOID, # lpSecurityAttributes
		ctypes.wintypes.DWORD, # dwCreationDisposition
		ctypes.wintypes.DWORD, # dwFlagsAndAttributes
		ctypes.wintypes.HANDLE # hTemplateFile
	)
	CloseHandle = ctypes.windll.kernel32.CloseHandle
	CloseHandle.restype = BOOL
	CloseHandle.argtypes = (HANDLE,)
	
	InfoStruct = CATALOG_INFO()
	WintrustStructure = WINTRUST_DATA()
	WintrustCatalogStructure = WINTRUST_CATALOG_INFO()
	WintrustFileStructure = WINTRUST_FILE_INFO()
	ctypes.memset(ctypes.byref(InfoStruct), 0x00, ctypes.sizeof(InfoStruct))
	ctypes.memset(ctypes.byref(WintrustStructure), 0x00, ctypes.sizeof(WintrustStructure))
	ctypes.memset(ctypes.byref(WintrustCatalogStructure), 0x00, ctypes.sizeof(WintrustCatalogStructure))
	ctypes.memset(ctypes.byref(WintrustFileStructure), 0x00, ctypes.sizeof(WintrustFileStructure))

	InfoStruct.cbStruct = ctypes.sizeof(InfoStruct)
	WintrustStructure.cbStruct = ctypes.sizeof(WintrustStructure)
	WintrustCatalogStructure.cbStruct = ctypes.sizeof(WintrustCatalogStructure)
	WintrustFileStructure.cbStruct = ctypes.sizeof(WintrustFileStructure)

	if not CryptCATAdminAcquireContext(ctypes.byref(Context), NULL, 0):
		return False
	
	FileHandle = CreateFileW(FilePath, GENERIC_READ, 7, NULL, OPEN_EXISTING, 0, NULL);
	if FileHandle == INVALID_HANDLE_VALUE:
		CryptCATAdminReleaseContext(Context, 0);
		return False
		
	CryptCATAdminCalcHashFromFileHandle(FileHandle, ctypes.byref(HashSize), NULL, 0)

	if HashSize == 0:
		CryptCATAdminReleaseContext(Context, 0);
		CloseHandle(FileHandle);
		return False

	Buffer = ctypes.create_string_buffer(HashSize.value)
	if not CryptCATAdminCalcHashFromFileHandle(FileHandle, ctypes.byref(HashSize), ctypes.byref(Buffer), 0):
		CryptCATAdminReleaseContext(Context, 0);
		CloseHandle(FileHandle);
		return False
	
	hash = ['{:02X}'.format(ord(byte)) for byte in Buffer.value]
	MemberTag = ''.join(hash)

	CatalogContext = CryptCATAdminEnumCatalogFromHash(Context, Buffer, HashSize, 0, NULL);
	if CatalogContext:
		if not CryptCATCatalogInfoFromContext(CatalogContext, ctypes.byref(InfoStruct), 0):
			# Release the context and set the context to null so it gets picked up below.
			CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0);
			CatalogContext = 0;

	if not CatalogContext:

		WintrustFileStructure.cbStruct = sizeof(WintrustFileStructure);
		WintrustFileStructure.pcwszFilePath = FilePath;
		WintrustFileStructure.hFile = NULL;
		WintrustFileStructure.pgKnownSubject = NULL;

		WintrustStructure.cbStruct = sizeof(WintrustStructure)
		WintrustStructure.dwUnionChoice = WTD_CHOICE_FILE
		WintrustStructure.pFile = ctypes.addressof(WintrustFileStructure)
		WintrustStructure.dwUIChoice = WTD_UI_NONE
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE
		WintrustStructure.dwStateAction = WTD_STATEACTION_IGNORE
		WintrustStructure.dwProvFlags = WTD_SAFER_FLAG
		WintrustStructure.hWVTStateData = NULL
		WintrustStructure.pwszURLReference = NULL
	else:

		# If we get here, we have catalog info!  Verify it.
		WintrustStructure.cbStruct = ctypes.sizeof(WintrustStructure)
		WintrustStructure.pPolicyCallbackData = LPVOID()
		WintrustStructure.pSIPClientData = LPVOID()
		WintrustStructure.dwUIChoice = WTD_UI_NONE
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE
		WintrustStructure.dwUnionChoice = WTD_CHOICE_CATALOG
		WintrustStructure.pCatalog = ctypes.addressof(WintrustCatalogStructure)
		WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY
		WintrustStructure.hWVTStateData = HANDLE()
		WintrustStructure.pwszURLReference = POINTER(WCHAR)()
		WintrustStructure.dwProvFlags = 0
		WintrustStructure.dwUIContext = WTD_UICONTEXT_EXECUTE

		# Fill in catalog info structure.
		WintrustCatalogStructure.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
		WintrustCatalogStructure.dwCatalogVersion = 0
		WintrustCatalogStructure.pcwszCatalogFilePath = InfoStruct.wszCatalogFile
		WintrustCatalogStructure.pcwszMemberTag = MemberTag
		WintrustCatalogStructure.pcwszMemberFilePath = FilePath
		WintrustCatalogStructure.hMemberFile = NULL

	
	# WINTRUST_ACTION_GENERIC_VERIFY_V2
	ActionGuid = GUID(0xaac56b,0xcd44,0x11d0,(BYTE * 8)(0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee))
	ReturnVal = WinVerifyTrust(0, ctypes.byref(ActionGuid), ctypes.addressof(WintrustStructure))
	
	if CatalogContext:
		CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0)
	
	# If we successfully verified, we need to free.
	if ReturnVal == 0:
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE
		WinVerifyTrust(0, ctypes.byref(ActionGuid), ctypes.addressof(WintrustStructure))
		
	CloseHandle(FileHandle)
	CryptCATAdminReleaseContext(Context, 0)
	
	if ReturnVal == 0:
		return True
	else:
		return False

def main():
	if len(sys.argv) < 2:
		print 'Usage: verify.py FILEPATH'
		sys.exit(1)
	print is_file_signed(sys.argv[1])
	
if __name__ == "__main__":
	main()