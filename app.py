from ctypes import sizeof
import psutil
import pymem
import io
from structs import CUser

if __name__ == '__main__':
    CUSER_ADDRESS = 0x061AAAB8
    CMOB_ADDRESS = 0x7D84AC0
    PROCESS_NAME = 'TMSRVIN.exe'

    print(sizeof(CUser))
    
    pm = pymem.Pymem("TMSRVIN.exe")

    base_address = pm.base_address
    process_handle = pm.process_handle

    cUser = (CUser * 1000)()

    buffer = pm.read_bytes(base_address + CUSER_ADDRESS, sizeof(cUser))

    io.BytesIO(buffer).readinto(cUser)

    for user in cUser:
        if user.AccoutName != b'':
            print(user.AccountName)