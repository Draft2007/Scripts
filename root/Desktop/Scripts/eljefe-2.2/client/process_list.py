from ctypes import byref, create_unicode_buffer, sizeof, WinDLL
from ctypes.wintypes import DWORD, HMODULE, MAX_PATH, BOOL, HANDLE

Psapi = WinDLL('Psapi.dll')
Kernel32 = WinDLL('kernel32.dll')

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

LIST_MODULES_ALL = 0x03

def EnumProcesses():
    buf_count = 256
    while True:
        buf = (DWORD * buf_count)()
        buf_size = DWORD(0)
        buf_size = sizeof(buf)
        res_size = DWORD(0)
        res = BOOL()
        res = Psapi.EnumProcesses(byref(buf), buf_size, byref(res_size))
        if not res:
            raise OSError('EnumProcesses failed')
        if res_size.value >= buf_size:
            buf_count *= 2
            continue
        count = res_size.value // (buf_size // buf_count)
        return buf[:count]

def EnumProcessModulesEx(hProcess):
    buf_count = 256
    LPDWORD
    while True:
        buf = (HMODULE * buf_count)()
        buf_size = DWORD(sizeof(buf))
        needed = DWORD(0)
        res = BOOL()
        res = Psapi.EnumProcessModulesEx(hProcess, byref(buf), buf_size,
                                          byref(needed), LIST_MODULES_ALL)
        if not res:
            raise OSError('EnumProcessModulesEx failed')
        if buf_size < needed.value:
            buf_count = needed.value // (buf_size // buf_count)
            continue
        count = needed.value // (buf_size // buf_count)
        return map(HMODULE, buf[:count])

def GetModuleFileNameEx(hProcess, hModule):
    buf = create_unicode_buffer(MAX_PATH)
    nSize = DWORD(0)
    res = DWORD(0)
    res = Psapi.GetModuleFileNameExW(hProcess, hModule,
                                      byref(buf), byref(nSize))
    if not res:
        raise OSError('GetModuleFileNameEx failed')
    return buf.value


def get_process_modules(pid):
    hProcess = HANDLE(0)
    hProcess = Kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False, pid)
    if not hProcess:
        raise OSError('Could not open PID %s' % pid)
    try:
        return [
            GetModuleFileNameEx(hProcess, hModule)
            for hModule in EnumProcessModulesEx(hProcess)]
    finally:
        Kernel32.CloseHandle(hProcess)

def get_process_name(pid):
    hProcess = HANDLE(0)
    hProcess = Kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False, pid)
    if not hProcess:
        raise OSError('Could not open PID %s' % pid)
    try:
        return GetModuleFileNameEx(hProcess, 0)
    finally:
        Kernel32.CloseHandle(hProcess)
        
def get_processes_names():
    processes = []
    for pid in EnumProcesses():
        try:
            processes.append(get_process_name(pid))
        except OSError as ose:
            print(str(ose))
    return processes
    
print get_processes_names()   
    