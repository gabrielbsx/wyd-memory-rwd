import ctypes
import psutil

if __name__ == '__main__':
    process_name = 'TMSrv.exe'
    pid = 0x0

    for proc in psutil.process_iter():
        try:
            if process_name in proc.name():
                pid = proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            exit()

    CUser_Addr = 0x61AAAB8
    CMob_Addr = 0x7D84AC0

    print(pid, CUser_Addr, CMob_Addr)

    pass