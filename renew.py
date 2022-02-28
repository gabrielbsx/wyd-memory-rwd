from ctypes import c_short, c_ushort, sizeof
from scapy.all import *
from io import BytesIO
from structs import P333, P334, CUser, CMob, PacketHeader
from base import Keys
import pymem
import requests
API = 'https://www.wydunderworld.com'
TOKEN_API = 'daskd435$@$fgdg812!@!@fU'

class Sniffer():
    def __init__(self):
        self.pm = pymem.Pymem('TMSRVIN.exe')
        self.cUser = (CUser * 1000)()
        self.cMob = (CMob * 12800)()
        self.cUserBuffer = self.pm.read_bytes(0x061AAAB8, sizeof(self.cUser))
        self.cMobBuffer = self.pm.read_bytes(0x07D84AC0, sizeof(self.cMob))
        BytesIO(self.cUserBuffer).readinto(self.cUser)
        BytesIO(self.cMobBuffer).readinto(self.cMob)
        self.filter = 'tcp and port 8281'
        self.iface = 'Intel(R) I350 Gigabit Network Connection #2'

    def reloadBuffers(self):
        self.cUserBuffer = self.pm.read_bytes(0x061AAAB8, sizeof(self.cUser))
        self.cMobBuffer = self.pm.read_bytes(0x07D84AC0, sizeof(self.cMob))
        BytesIO(self.cUserBuffer).readinto(self.cUser)
        BytesIO(self.cMobBuffer).readinto(self.cMob)
        
    def run(self):
        sniff(filter=self.filter, prn=self.parse_packet, iface=self.iface, store=0)

    def split_packet(self, packet):
        packet = bytearray(packet)
        initial_packet = 0
        packets = []
        
        while initial_packet < len(packet):
            try: 
                packet_size = c_ushort()
                BytesIO(packet[initial_packet:initial_packet+2]).readinto(packet_size)
                packet_size = packet_size.value

                packets.append(bytes(packet[initial_packet:initial_packet+packet_size]))
                initial_packet += packet_size

                if initial_packet >= len(packet) or packet_size == 0:
                    break
            except Exception as err:
                print('Split: ', err)
                break
            
        return packets

    def decrypt(self, data):
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
        except Exception as err:
            print('Decrypt: ', err)
            return None

    def parse_packet(self, packet):
        if not packet.haslayer(TCP):
            return

        #if packet[IP].src != '189.1.170.170':
        #    return

        buffer = bytes(packet[TCP].payload)
        buffers = self.split_packet(buffer)
        #self.reloadBuffers()

        for data in buffers:
            if len(data) < 4:
                return

            data = self.decrypt(data)

            packetHeader = PacketHeader()

            BytesIO(data).readinto(packetHeader)

            if packetHeader.PacketId == 0x334:
                if packet.dst != 'ac:1f:6b:fb:a3:b4':
                    return
                self.reloadBuffers()
                PacketData = P334()
                BytesIO(data).readinto(PacketData)

                requests.post(f'{API}/api/v1/chat-messages', data={
                    'username': self.cUser[int(PacketData.Header.ClientId)].AccountName.decode('latin1'),
                    'nick': self.cMob[int(PacketData.Header.ClientId)].Mob.Name.decode('latin1'),
                    'message': PacketData.Arg.decode('latin1'),
                    'color': PacketData.Color,
                    'command': PacketData.Cmd.decode('latin1'),
                })
                print('PacketId: {} Command: {} Message: {}'.format(hex(PacketData.Header.PacketId), PacketData.Cmd, PacketData.Arg.decode('latin1')))
                

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.run()