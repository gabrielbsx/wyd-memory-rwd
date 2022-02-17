import pymem
import requests
from io import BytesIO
from ctypes import c_short, sizeof
from structs import P333, P334, P338, P364, P366, P666, CUser, CMob, PacketHeader
from tabulate import tabulate
from base import Keys
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
API = 'https://5d1b-2804-431-c7fd-a066-993a-4c23-86e6-70b4.ngrok.io'

def loadBuffers() -> None:
    global cUser, cMob, pm, CUSER_ADDRESS, CMOB_ADDRESS
    cUserBuffer = pm.read_bytes(CUSER_ADDRESS, sizeof(cUser))
    cMobBuffer = pm.read_bytes(CMOB_ADDRESS, sizeof(cMob))
    io.BytesIO(cUserBuffer).readinto(cUser)
    io.BytesIO(cMobBuffer).readinto(cMob)

class Packet_666(): #PACKET KILL
    def __init__(self, buffer: bytes):
        self.packet = P666()
        BytesIO(buffer).readinto(self.packet)
        self.run()

    def getMobNameKiller(self) -> str:
        return cMob[self.packet.KillerID.value].Mob.Name.decode('latin1')

    def getMobNameKilled(self) -> str:
        return cMob[self.packet.KilledID.value].Mob.Name.decode('latin1')

    def getUsernameKiller(self) -> str:
        return cUser[self.packet.KillerID.value].AccountName.decode('latin1')

    def getUsernameKilled(self) -> str:
        return cUser[self.packet.KilledID.value].AccountName.decode('latin1')

    def getPosition(self) -> dict[int]:
        return { 'x': self.packet.Pos.X.value, 'y': self.packet.Pos.Y.value }

    def run(self) -> None:
        requests.post(f'{API}/api/v1/kill', data={
            'killer': self.getUsernameKiller(),
            'killed': self.getUsernameKilled(),
            'killer_mob': self.getMobNameKiller(),
            'killed_mob': self.getMobNameKilled(),
            'x': self.getPosition().x,
            'y': self.getPosition().y,
        })

class Packet_333(): #COMMON CHAT MESSAGE
    def __init__(self, buffer: bytes):
        self.packet = P333()
        BytesIO(buffer).readinto(self.packet)
        self.run()

    def getMessage(self) -> str:
        return self.packet.String.decode('latin1')

    def getUsername(self) -> str:
        return cUser[self.packet.Heeader.ClientId.value].AccountName.decode('latin1')
    
    def getMobName(self) -> str:
        return cMob[self.packet.Header.ClientId.value].Mob.Name.decode('latin1')

    def run(self) -> None:
        print(f'[{hex(self.packet.Header.PacketId)}][{self.getUsername()}] {self.getMobName()}: {self.getMessage()}')
        return

class Packet_334(): #GLOBAL CHAT MESSAGE OR MESSAGE WITH COMMAND
    def __init__(self, buffer) -> None:
        self.packet = P334()
        BytesIO(buffer).readinto(self.packet)
        self.run()

    def getColor(self) -> int:
        return self.packet.Color
        
    def getCommand(self) -> str:
        return self.packet.Cmd.decode('latin1')

    def getMessage(self) -> str:
        return self.packet.Arg.decode('latin1')

    def getUsername(self) -> str:
        return cUser[self.packet.Header.ClientId].AccountName.decode('latin1')

    def getMobName(self) -> str:
        return cMob[self.packet.Header.ClientId].Mob.Name.decode('latin1')

    def run(self) -> None:
        requests.post(f'{API}/api/v1/chat-messages', data={
            'username': self.getUsername(),
            'nick': self.getMobName(),
            'message': self.getMessage(),
            'color': self.getColor(),
            'command': self.getCommand(),
        })
        return


class PacketManager(object): #PACKET MANAGER
    def __init__(self, data: bytes) -> None:
        self.buffers = []
        self.buffer = data
        self.splitBuffer()
        self.bufferIterator()
        self.instancePacket = {
            0x334: Packet_334,
            0x333: Packet_333,
            #0x338: Packet_338,
            #0x364: Packet_364,
            #0x366: Packet_366,
            0x666: Packet_666,
        }

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
        data = bytearray(data)
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

    def splitBuffer(self) -> None:
        packet_size = c_short() 
        packet_size.value = 0
        initial_bytes = 0
        while initial_bytes < len(self.buffer):
            io.BytesIO(self.buffer[initial_bytes:initial_bytes + 2]).readinto(packet_size)
            n_buffer = self.buffer[initial_bytes:packet_size.value + initial_bytes]
            self.buffers.append(n_buffer)
            initial_bytes = initial_bytes + packet_size.value

    def bufferIterator(self) -> None:
        for buffer in self.buffers:
            packet_header = PacketHeader()
            io.BytesIO(buffer).readinto(packet_header)
            packet_id = packet_header.PacketId
            client_id = packet_header.ClientId
            if client_id not in range(0, 1000):
                continue
            if packet_id in self.instancePacket.keys():
                self.instancePacket[packet_id](buffer)

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

        self.packetManager(buffer[Raw].load)

class Application(PacketHandle): #APPLICATION SNIFFER
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