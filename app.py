from asyncio import Future
import pymem
import io
import requests
from ctypes import c_short, sizeof
from structs import P334, CUser, CMob, PacketHeader
from tabulate import tabulate
from base import Keys
from scapy.all import *

BASE_ADDRESS = 0x00401000
CUSER_ADDRESS = 0x061AAAB8
CMOB_ADDRESS = 0x07D84AC0
PROCESS_NAME = 'TMSRVIN.exe'
cUser = (CUser * 1000)()
cMob = (CMob * 1000)()
#pm = pymem.Pymem("TMSRVIN.exe")
IFACE = 'Intel(R) PRO/1000 MT Network Connection'
FILTER = 'tcp and port 8281 and host 135.148.49.138'
SERVER_IP = '135.148.49.138'

def decrypt(data: bytes) -> bytes:
    data = bytearray(data)
    
    packet_size = len(data)
    packet_key = data[2]

    keyword = Keys[0:][2 * (packet_key & 0xFF)]
    sum1, sum2 = (0, 0)
    
    for i in range(4, packet_size):
        sum1 += data[i]
        key_byte = Keys[1:][2 * (keyword & 0xFF)]
        
        if (i & 0x03) == 0:
            data[i] = (data[i] - (key_byte << 0x01)) & 0xFF
        elif (i & 0x03) == 1:
            data[i] = (data[i] + (key_byte >> 0x03)) & 0xFF
        elif (i & 0x03) == 2:
            data[i] = (data[i] - (key_byte << 0x02)) & 0xFF
        elif (i & 0x03) == 3:
            data[i] = (data[i] + (key_byte >> 0x05)) & 0xFF
        sum2 += data[i]

        keyword += 1
    return bytes(data) if data[3] == (sum1 - sum2) & 0xFF else None

def loadBuffers() -> None:
    global cUser, cMob, pm, CUSER_ADDRESS, CMOB_ADDRESS

    cUserBuffer = pm.read_bytes(CUSER_ADDRESS, sizeof(cUser))
    cMobBuffer = pm.read_bytes(CMOB_ADDRESS, sizeof(cMob))
    
    io.BytesIO(cUserBuffer).readinto(cUser)
    io.BytesIO(cMobBuffer).readinto(cMob)

class PacketManager(object):
    def __init__(self, data: bytes) -> None:
        self.buffers: List[bytes] = []
        self.buffer: bytes = data
        self.splitBuffer()

    def decrypt(self, data: bytes) -> bytes:
        data = bytearray(data)
        packet_size = len(data)
        packet_key = data[2]
        keyword = Keys[0:][2 * (packet_key & 0xFF)]
        sum1, sum2 = (0, 0)
        for i in range(4, packet_size):
            sum1 += data[i]
            key_byte = Keys[1:][2 * (keyword & 0xFF)]
            if (i & 0x03) == 0:
                data[i] = (data[i] - (key_byte << 0x01)) & 0xFF
            elif (i & 0x03) == 1:
                data[i] = (data[i] + (key_byte >> 0x03)) & 0xFF
            elif (i & 0x03) == 2:
                data[i] = (data[i] - (key_byte << 0x02)) & 0xFF
            elif (i & 0x03) == 3:
                data[i] = (data[i] + (key_byte >> 0x05)) & 0xFF
            sum2 += data[i]
            keyword += 1
        return bytes(data) if data[3] == (sum1 - sum2) & 0xFF else None

    def encrypt(self, data: bytes) -> bytes:
        data = bytearray(buffer)
        packet_size = len(data)
        packet_key = data[2]
        keyword = Keys[0:][2 * (packet_key & 0xFF)]
        sum1, sum2 = (0, 0)
        for i in range(4, packet_size):
            sum1 += data[i]
            key_byte = Keys[1:][2 * (keyword & 0xFF)]
            if (i & 0x03) == 0:
                data[i] = (data[i] + (key_byte << 0x01)) & 0xFF
            elif (i & 0x03) == 1:
                data[i] = (data[i] - (key_byte >> 0x03)) & 0xFF
            elif (i & 0x03) == 2:
                data[i] = (data[i] + (key_byte << 0x02)) & 0xFF
            elif (i & 0x03) == 3:
                data[i] = (data[i] - (key_byte >> 0x05)) & 0xFF
            sum2 += data[i]
            keyword += 1
        return bytes(data) if data[3] == (sum1 - sum2) & 0xFF else None

    async def splitBuffer(self) -> Future[None]:
        packet_id = 0
        packet_size = c_short()
        packet_size.value = 0

        while packet_id * packet_size < len(self.buffer):
            io.BytesIO(self.buffer[packet_id * packet_size:packet_id * packet_size + 2]).readinto(packet_size)
            self.buffers.append(self.buffer[packet_id * packet_size:packet_id * packet_size + packet_size.value + 2])
            packet_id += 1


class PacketHandle(PacketManager):
    def __init__(self) -> None:
        self.packetManager = super().__init__

    def validateBuffer(self, buffer: bytes) -> bool:
        if buffer[IP].src == SERVER_IP:
            return False
        if not buffer.haslayer(Raw):
            return False
        return True

    def handle(self, buffer: bytes) -> None:
        if not self.validateBuffer(buffer):
            return
            
        self.packetManager(buffer)

        return
            
        '''if header.PacketId == 0x334:
            loadBuffers()
            p334 = P334()
            io.BytesIO(payload).readinto(p334)
            message = p334.Arg.decode('latin')

            if message[0] == '@':
                index = p334.Header.ClientId
                mobname = cMob[index].Mob.Name.decode('latin1')

                requests.post('http://c06f-2804-7f0-b180-9394-6c01-9c64-d930-6ef5.ngrok.io/api/v1/chat-messages', data={'message': message, 'nick': mobname})
        '''

class Application(PacketHandle):
    def __init__(self) -> None:
        self.table = []
        PacketHandle.__init__(self)

    def loadTable(self) -> None:
        global cUser, cMob
        for user, mob, index in zip(cUser, cMob, range(0, 1000)):
            if user.AccountName != b'':
                self.table.append([
                    index,
                    user.AccountName.decode('latin1'),
                    mob.Mob.Name.decode('latin1'),
                    mob.Mob.BaseStatus.Level + 1,
                    mob.Mob.Class,
                    mob.Mob.GuildId
                ])

    def dumpTable(self) -> None:
        print(tabulate(self.table, ['ID', 'CONTA', 'PERSONAGEM', 'LEVEL', 'KINGDOM', 'CLASS', 'GUILD']))

    def initialize(self) -> None:
        global IFACE, FILTER, SERVER_IP
        sniff(iface=IFACE, filter=FILTER, store=0, prn=self.handle)

if __name__ == '__main__':
    app = Application()
    app.initialize()