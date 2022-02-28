import pymem
import requests
from io import BytesIO
from ctypes import c_short, sizeof, c_ushort
from structs import P333, P334, P338, P364, P366, P666, CUser, CMob, PacketHeader
from tabulate import tabulate
from base import Keys
from scapy.all import *

BASE_ADDRESS = 0x00401000
CUSER_ADDRESS = 0x061AAAB8
CMOB_ADDRESS = 0x07D84AC0
PROCESS_NAME = 'TMSRVIN.exe'
cUser = (CUser * 1000)()
cMob = (CMob * 12800)()
pm = pymem.Pymem("TMSRVIN.exe")
#IFACE = 'Intel(R) PRO/1000 MT Network Connection'
IFACE = 'Intel(R) I350 Gigabit Network Connection #2'
FILTER = 'tcp and port 8281'
SERVER_IP = '189.1.170.170'
API = 'https://www.wydunderworld.com'
TOKEN_API = 'daskd435$@$fgdg812!@!@fU'
TABLE = []

def loadBuffers() -> None:
    cUserBuffer = pm.read_bytes(CUSER_ADDRESS, sizeof(cUser))
    cMobBuffer = pm.read_bytes(CMOB_ADDRESS, sizeof(cMob))
    io.BytesIO(cUserBuffer).readinto(cUser)
    io.BytesIO(cMobBuffer).readinto(cMob)

def loadTable() -> None:
    for user, mob, index in zip(cUser, cMob, range(0, 1000)):
        if user.AccountName != b'':
            TABLE.append([
                index,
                user.AccountName.decode('latin1'),
                mob.Mob.Name.decode('latin1'),
                mob.Mob.BaseStatus.Level + 1,
                mob.Mob.Class,
                mob.Mob.GuildId
            ])

def dumpTable() -> None:
    print(tabulate(TABLE, ['ID', 'CONTA', 'PERSONAGEM', 'LEVEL', 'KINGDOM', 'CLASS', 'GUILD']))

class Packet_666(): #PACKET KILL
    def __init__(self, buffer: bytes):
        self.packet = P666()
        BytesIO(buffer).readinto(self.packet)
        self.run()

    def getMobNameKiller(self) -> str:
        return cMob[self.packet.KillerID].Mob.Name.decode('latin1')

    def getMobNameKilled(self) -> str:
        return cMob[self.packet.KilledID].Mob.Name.decode('latin1')

    def getUsernameKiller(self) -> str:
        if self.packet.KillerID < 0 or self.packet.KillerID > 1000:
            return ''
        return cUser[self.packet.KillerID].AccountName.decode('latin1')

    def getUsernameKilled(self) -> str:
        if self.packet.KilledID < 0 or self.packet.KilledID > 1000:
            return ''
        return cUser[self.packet.KilledID].AccountName.decode('latin1')

    def getPosition(self) -> dict[int]:
        return [self.packet.Pos.X, self.packet.Pos.Y]

    def run(self) -> None:
        print(f'{self.getMobNameKiller()} killed {self.getMobNameKilled()} at {self.getPosition()}')
        requests.post(f'{API}/api/v1/kill', data={
            'killer': self.getUsernameKiller(),
            'killed': self.getUsernameKilled(),
            'killer_mob': self.getMobNameKiller(),
            'killed_mob': self.getMobNameKilled(),
            'x': self.getPosition()[0],
            'y': self.getPosition()[1],
        })

class Packet_333(): #COMMON CHAT MESSAGE
    def __init__(self, buffer: bytes):
        self.packet = P333()
        BytesIO(buffer).readinto(self.packet)
        self.run()

    def getMessage(self) -> str:
        return self.packet.String.decode('latin1')

    def getUsername(self) -> str:
        return cUser[self.packet.Header.ClientId].AccountName.decode('latin1')
    
    def getMobName(self) -> str:
        return cMob[self.packet.Header.ClientId].Mob.Name.decode('latin1')

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
        print(f'[{hex(self.packet.Header.PacketId)}][{self.getUsername()}] {self.getMobName()}: {self.getMessage()}')
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
        self.buffer = bytearray(data)
        self.instancePacket = {
            0x334: Packet_334,
            #0x333: Packet_333,
            #0x666: Packet_666,
        }
        self.splitBuffer()
        self.bufferIterator()

    def decrypt(self, data: bytes) -> bytes:
        try:
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
        except:
            print('[!] Decryption error')
            return None

    def encrypt(self, data: bytes) -> bytes:
        try:
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
        except:
            print('[!] Encryption error')
            return None

    def splitBuffer(self) -> None:
        packet_size = c_ushort() 
        packet_size.value = 0
        initial = 0
        size_increment = 0

        while True:
            try:
                io.BytesIO(self.buffer[initial:initial+2]).readinto(packet_size)
                size_increment += packet_size.value
                n_buffer = self.buffer[initial:packet_size.value + initial]
                self.buffers.append(bytes(n_buffer))
                initial = initial + packet_size.value

                if packet_size.value == 0 or packet_size.value >= len(self.buffer) or packet_size.value < 0 or initial >= len(self.buffer):
                    break
            except:
                print('[!] Error while splitting buffer')
                break
   
    def isRepeatedPacket(self, data: bytes) -> bool:
        response = requests.post(f'{API}/api/v1/packet-check', headers={
            'authorization': TOKEN_API,
        }, data={
            'packet': data.hex(),
        })

        if response.status_code == 200:
            return True
        
        return False

    def addPacket(self, data: bytes) -> None:
        requests.post(f'{API}/api/v1/add-packet', headers={
            'authorization': TOKEN_API,
        }, data={
            'packet': data.hex()
        })
    
    def bufferIterator(self) -> None:
        for buffer in self.buffers:
            if len(buffer) < 4:
                continue

            buffer = self.decrypt(buffer)

            if buffer is None or len(buffer) < 12:
                continue

            packet_header = PacketHeader()
            io.BytesIO(buffer).readinto(packet_header)
            packet_id = packet_header.PacketId
            client_id = packet_header.ClientId

            #print(hex(packet_id))
            if packet_id == 0x334:
                print('teste1')
            if packet_id in self.instancePacket:
                print('teste2')
            if packet_header.PacketId in self.instancePacket.keys():
                #if self.isRepeatedPacket(buffer):
                #    continue
                #self.addPacket(buffer)
                self.instancePacket[packet_id](buffer)

def validateBuffer(buffer: bytes) -> bool:
    #if buffer[IP].src == SERVER_IP:
    #    return False
    if not buffer.haslayer(TCP):
        return False
    return True

def handle(buffer: bytes) -> None:
    if not validateBuffer(buffer):
        return

    loadBuffers()
    #loadTable()
    #dumpTable()
    PacketManager(bytes(buffer[TCP].payload))

if __name__ == '__main__':
    loadBuffers()
    loadTable()
    dumpTable()
    sniff(iface=IFACE, filter=FILTER, store=0, prn=handle)