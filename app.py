import pymem
import io
import requests
from ctypes import sizeof
from structs import P334, CUser, CMob, PacketHeader
from tabulate import tabulate
from base import decrypt
from scapy.all import *

BASE_ADDRESS = 0x00401000
CUSER_ADDRESS = 0x061AAAB8
CMOB_ADDRESS = 0x07D84AC0
PROCESS_NAME = 'TMSRVIN.exe'
cUser = (CUser * 1000)()
cMob = (CMob * 1000)()
pm = pymem.Pymem("TMSRVIN.exe")
IFACE = 'Intel(R) PRO/1000 MT Network Connection'
FILTER = 'tcp and port 8281 and host 135.148.49.138'
SERVER_IP = '135.148.49.138'

def loadBuffers() -> None:
    global cUser, cMob, pm, CUSER_ADDRESS, CMOB_ADDRESS

    cUserBuffer = pm.read_bytes(CUSER_ADDRESS, sizeof(cUser))
    cMobBuffer = pm.read_bytes(CMOB_ADDRESS, sizeof(cMob))
    
    io.BytesIO(cUserBuffer).readinto(cUser)
    io.BytesIO(cMobBuffer).readinto(cMob)

class PacketHandle():
    def __init__(self) -> None:
        self.packetIds = [0x333, 0x334,]

    def validateBuffer(self, buffer: bytes) -> bool:
        if buffer[IP].src == SERVER_IP:
            return False

        if not buffer.haslayer(Raw):
            return False

        return True

    def validatePacket(self, payload: bytes) -> bool | PacketHeader:
        header = PacketHeader()

        io.BytesIO(payload).readinto(header)

        if not header.PacketId in self.packetIds:
            return False

        return header


    def handle(self, buffer: bytes) -> None:
        if not self.validateBuffer(buffer):
            return

        payload = decrypt(bytes(buffer[Raw].load))

        header = self.validatePacket(payload)

        if not header:
            return

        if header.PacketId == 0x334:
            loadBuffers()
            p334 = P334()
            io.BytesIO(payload).readinto(p334)
            message = p334.Arg.decode('latin')

            if message[0] == '@':
                index = p334.Header.ClientId
                mobname = cMob[index].Mob.Name.decode('latin1')

                requests.post('http://c06f-2804-7f0-b180-9394-6c01-9c64-d930-6ef5.ngrok.io/api/v1/chat-messages', data={'message': message, 'nick': mobname})


class Application(PacketHandle):
    def __init__(self) -> None:
        self.table = []
        PacketHandle.__init__(self)

    def loadTable(self) -> None:
        global cUser, cMob

        for user, mob, index in zip(cUser, cMob, range(0, 1000)):
            if user.AccountName != b'':
                self.table.append([index, user.AccountName.decode('latin1'), mob.Mob.Name.decode('latin1'), mob.Mob.BaseStatus.Level + 1, mob.Mob.Class, mob.Mob.GuildId])


    def dumpTable(self) -> None:
        print(tabulate(self.table, ['ID', 'CONTA', 'PERSONAGEM', 'LEVEL', 'KINGDOM', 'CLASS', 'GUILD']))

    def initialize(self) -> None:
        global IFACE, FILTER, SERVER_IP
        sniff(iface=IFACE, filter=FILTER, store=0, prn=self.handle)

if __name__ == '__main__':
    app = Application()
    app.initialize()