from ctypes import sizeof
import pymem
import io
from structs import P334, CUser, CMob, PacketHeader
from tabulate import tabulate
from base import decrypt
from scapy import sniff

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

class Application():
    def __init__(self) -> None:
        self.table = []

    def loadTable(self) -> None:
        global cUser, cMob

        for user, mob, index in zip(cUser, cMob, range(0, 1000)):
            if user.AccountName != b'':
                self.table.append([index, user.AccountName.decode('latin1'), mob.Mob.Name.decode('latin1'), mob.Mob.BaseStatus.Level + 1, mob.Mob.Class, mob.Mob.GuildId])


    def dumpTable(self) -> None:
        print(tabulate(self.table, ['ID', 'CONTA', 'PERSONAGEM', 'LEVEL', 'KINGDOM', 'CLASS', 'GUILD']))

    def packet_handle(self, packet: bytes) -> None:
        if packet[IP].src != self.server_ip:
            return

        if not packet.haslayer(Raw):
            return

        payload = bytes(packet.getlayer(Raw).load)
        decrypted = decrypt(payload)

        header = PacketHeader()
        io.BytesIO(decrypted).readinto(header)

        if header.PacketId == None:
            return

        loadBuffers()

        if header.PacketId == 0x334:
            stPacket = P334()
            io.BytesIO(decrypted).readinto(stPacket)

            message = stPacket.Arg.decode('latin')
            if message[0] == '@':
                print(message)

        return


    def initialize(self) -> None:
        global IFACE, FILTER, SERVER_IP
        sniff(iface=IFACE, filter=FILTER, store=0, prn=self.packet_handle)


if __name__ == '__main__':
    app = Application()
    app.initialize()