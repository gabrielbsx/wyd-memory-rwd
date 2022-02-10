from ctypes import sizeof
import pymem
import io
from structs import CUser, CMob
from tabulate import tabulate
import scapy

BASE_ADDRESS = 0x00401000
CUSER_ADDRESS = 0x061AAAB8
CMOB_ADDRESS = 0x07D84AC0
PROCESS_NAME = 'TMSRVIN.exe'
cUser = (CUser * 1000)()
cMob = (CMob * 1000)()

def loadBuffers() -> None:
    global cUser, cMob
    pymem.read_bytes(CUSER_ADDRESS, sizeof(cUser))
    pymem.read_bytes(CMOB_ADDRESS, sizeof(cMob))
    return

if __name__ == '__main__':
    

    pm = pymem.Pymem("TMSRVIN.exe")

    cUserBuffer = pm.read_bytes(CUSER_ADDRESS, sizeof(cUser))
    cMobBuffer = pm.read_bytes(CMOB_ADDRESS, sizeof(cMob))

    io.BytesIO(cUserBuffer).readinto(cUser)
    io.BytesIO(cMobBuffer).readinto(cMob)

    table = []

    for user, mob, index in zip(cUser, cMob, range(0, 1000)):
        if user.AccountName != b'':
            table.append([index, user.AccountName.decode('latin1'), mob.Mob.Name.decode('latin1'), mob.Mob.BaseStatus.Level + 1, mob.Mob.Class, mob.Mob.GuildId])

    print(tabulate(table, ['ID', 'CONTA', 'PERSONAGEM', 'LEVEL', 'KINGDOM', 'CLASS', 'GUILD']))