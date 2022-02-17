from ctypes import *

#VERSION 7559

class STRUCT_POSITION(Structure):
    _fields_ = [
        ('X', c_uint16),
        ('Y', c_uint16),
    ]

class STRUCT_EFFECT(Structure):
    _fields_ = [
        ('sEffect', c_ubyte),
        ('sValue', c_ubyte),
    ]

class STRUCT_ITEM(Structure):
    _fields_ = [
        ('sIndex', c_short),
        ('stEffect', STRUCT_EFFECT * 3),
    ]

class STRUCT_SCORE(Structure):
    _fields_ = [
        ('Level', c_short),
        ('padding', c_short),
        ('Defense', c_int),
        ('Attack', c_int),
        ('Merchant', c_ubyte),
        ('ChaosRate', c_ubyte),
        ('padding2', c_short),
        ('maxHP', c_int),
        ('maxMP', c_int),
        ('curHP', c_int),
        ('curMP', c_int),
        ('STR', c_short),
        ('INT', c_short),
        ('DEX', c_short),
        ('CON', c_short),
        ('Masteries', c_short * 4),
    ]

class CPSock(Structure):
    _fields_ = [
        ("Sock", c_uint),
        ("pSendBuffer", c_char_p),
        ("pRecvBuffer", c_char_p),
        ("nSendPosition", c_int),
        ("nRecvPosition", c_int),
        ("nProcPosition", c_int),
        ("nSentPosition", c_int),
        ("Init", c_int),
        ("SendQueue", c_char * 16),
        ("RecvQueue", c_char * 16),
        ("SendCount", c_int),
        ("RecvCount", c_int),
        ("ErrCount", c_int),
    ]

class STRUCT_AFFECT(Structure):
    _fields_ = [
        ('Type', c_ubyte),
        ('Level', c_ubyte),
        ('Value', c_short),
        ('Time', c_int),
    ]

class STRUCT_EXT1(Structure):
    _fields_ = [
        ("Data", c_int * 8),
        ("Affect", STRUCT_AFFECT * 32)
    ]

class STRUCT_SUBCLASS(Structure):
    _fields_ = [
        ("LearnedSkill", c_uint * 2),
        ("Equip", STRUCT_ITEM),
        ("CurrentScore", STRUCT_SCORE),
        ("Exp", c_longlong),
        ("ShortSkill", c_char * 20),
        ("ScoreBonus", c_short),
        ("SkillBonus", c_short)
    ]

class STRUCT_EXT2(Structure):
    _fields_ = [
        ('Quest', c_char * 12),
        ('LastConnectTime', c_uint),
        ('SubClass', STRUCT_SUBCLASS * 2),
        ('ItemPassWord', c_char * 16),
        ('ItemPos', c_uint),
        ('SendLevItem', c_int),
        ('AdminGuildItem', c_short),
        ('Dummy', c_char * 126)
    ]

class STRUCT_SELCHAR(Structure):
    _fields_ = [
        ("HomeTownX", c_ushort * 4),
        ("HomeTownY", c_ushort * 4),
        ("MobName", c_char * 4 * 16),
        ("Score", STRUCT_SCORE * 4),
        ("Equip", STRUCT_ITEM * 4 * 16),
        ("Guild", c_ushort * 4),
        ("Coin", c_int * 4),
        ("Exp", c_longlong * 4)
    ]

class MSG_Trade(Structure):
    _fields_ = [
        ("Size", c_uint16),
        ("KeyWord", c_uint8),
        ("CheckSum", c_uint8),
        ("Type", c_uint16),
        ("ID", c_uint16),
        ("Tick", c_uint),
        ("Item", STRUCT_ITEM * 15),
        ("CarryPos", c_char * 15),
        ("TradeMoney", c_int),
        ("MyCheck", c_ubyte),
        ("OpponentID", c_ushort),
    ]

class MSG_AutoTrade(Structure):
    _fields_ = [
        ("Size", c_uint16),
        ("KeyWord", c_uint8),
        ("CheckSum", c_uint8),
        ("Type", c_uint16),
        ("ID", c_uint16),
        ("Tick", c_uint),
        ("Desc", c_char * 24),
        ("Item", STRUCT_ITEM * 12),
        ("CarryPos", c_char * 12),
        ("TradeMoney", c_int * 12),
        ("Tax", c_ushort),
        ("TargetID", c_ushort)
    ]

class STRUCT_MOB(Structure):
    _fields_ = [
        ('Name', c_char * 16),
        ('Clan', c_ubyte),
        ('Merchant', c_ubyte),
        ('GuildId', c_short),
        ('Class', c_ubyte),
        ('AffectInfo', c_ubyte),
        ('QuestInfo', c_short),
        ('Gold', c_int),
        ('Exp', c_longlong),
        ('GemPosition', STRUCT_POSITION),
        ('BaseStatus', STRUCT_SCORE),
        ('CurrentStatus', STRUCT_SCORE),
        ('Equip', STRUCT_ITEM * 16),
        ('Inventory', STRUCT_ITEM * 64),
        ('Learn', c_int),
        ('Learn2', c_int),
        ('StatusPoint', c_ushort),
        ('MasterPoint', c_ushort),
        ('SkillPoint', c_ushort),
        ('Critical', c_ubyte),
        ('SaveMana', c_ubyte),
        ('SkillBar', c_char * 4),
        ('GuildMemberType', c_byte),
        ('Padding', c_char),
        ('RegenHP', c_char),
        ('RegenMP', c_char),
        ('unks', c_ubyte * 203),
        ('Unk', c_char),
        ('Unk2', c_short),
        ('Resists', c_short * 4),
        ('Magic', c_short),
        ('KillPoint', c_short),
        ('Unk3', c_short),
    ]

class CMob(Structure):
    _fields_ = [
        ("Mob", STRUCT_MOB),
        ("Ext1", STRUCT_EXT1),
        ("Ext2", STRUCT_EXT2),
        ("Affects", STRUCT_AFFECT * 32),
        ("Tab", c_char * 26),
        ("unknow234", c_int),
        ("ProgressLevel", c_int),
        ("CreateType", c_int),
        ("SegmentX", c_int),
        ("SegmentY", c_int),
        ("SegmentListX", c_int * 5),
        ("SegmentListY", c_int * 5),
        ("SegmentWait", c_int * 5),
        ("SegmentDirection", c_int),
        ("SegmentProgress", c_int),
        ("GenerateIndex", c_int),
        ("TargetList", c_short * 4),
        ("PartyList", c_short * 12),
        ("unknow265", c_int),
        ("Mode", c_int),
        ("LeaderID", c_int),
        ("FormationType", c_int),
        ("RouteType", c_int),
        ("LastX", c_int),
        ("LastY", c_int),
        ("LastTime", c_int),
        ("LastSpeed", c_int),
        ("TargetX", c_int),
        ("TargetY", c_int),
        ("NextX", c_int),
        ("NextY", c_int),
        ("Action", c_int),
        ("Route", c_char * 24),
        ("WaitNextSegment", c_int),
        ("WeaponDamage", c_int),
        ("SummonID", c_int),
        ("PotionCount", c_int),
        ("GuildDisable", c_int),
        ("DropBonus", c_int),
        ("ExpBonus", c_int),
        ("AttackRange", c_int),
        ("StatusGenerate", c_int),
        ("unknow294", c_int),
        ("SaveFaceID", c_int),
        ("QuestID", c_int),
        ("isKefra", c_int),
        ("BossType", c_int),
        ("EmptyUnknow", c_int),
        ("SaveMotion", c_int),
        ("AnotherSkill", c_int),
        ("SaveSpeed", c_int),
        ("ServerIndex", c_int),
        ("RuneQuestID", c_int),
        ("SaveKingdom", c_int),
        ("DelayRegenHP", c_int),
        ("unknow307", c_int),
        ("unknow308", c_int),
        ("unknow309", c_int),
        ("unknow310", c_int),
        ("CurrHP", c_uint),
        ("ChickenDamage", c_int),
        ("SaveRegenHp", c_int),
        ("ForceDamage", c_int),
        ("ReflectDamage", c_int),
        ("InternalPremiumItem", c_int),
        ("SaveLeaderID", c_int),
        ("SaveLeaderID_2", c_int),
        ("UnknowSummonInfo", c_int),
        ("PvPExtraDamage", c_short),
        ("PvPExtraDefense", c_short),
        ("SummonList", c_short * 12),
        ("RsvJewels", c_int),
        ("RsvJewels_2", c_int),
        ("ExtraCons", c_int),
        ("BonusEvasion", c_int),
    ]

class CUser(Structure):
    _fields_ = [
        ("AccountName", c_char * 16),
        ("Slot", c_int),
        ("IP", c_uint),
        ("Mode", c_int),
        ("TradeMode", c_int),
        ("cSock", CPSock),
        ("Cargo", STRUCT_ITEM * 128),
        ("Coin", c_int),
        ("cProgress", c_ushort),
        ("UnknowByte_1138", c_short),
        ("Trade", MSG_Trade),
        ("AutoTrade", MSG_AutoTrade),
        ("LastAttack", c_int),
        ("LastAttackTick", c_uint),
        ("LastMove", c_int),
        ("LastAction", c_int),
        ("LastActionTick", c_uint),
        ("LastIllusionTick", c_uint),
        ("NumError", c_uint),
        ("SelChar", STRUCT_SELCHAR),
        ("LastChat", c_char * 16),
        ("Session", c_char * 36),
        ("CharShortSkill", c_char * 16),
        ("nTargetX", c_int),
        ("nTargetY", c_int),
        ("Whisper", c_int),
        ("Guildchat", c_int),
        ("PartyChat", c_int),
        ("Chatting", c_int),
        ("UnknowByte_2452", c_int),
        ("AutoTradeName", c_char * 24),
        ("PKMode", c_int),
        ("ReqHp", c_int),
        ("ReqMp", c_int),
        ("bQuaff", c_int),
        ("Mac", c_char * 16),
        ("RankingMode", c_int),
        ("RankingTarget", c_int),
        ("RankingType", c_int),
        ("LastReceiveTime", c_int),
        ("Admin", c_int),
        ("Child", c_int),
        ("CheckBillingTime", c_uint),
        ("CharLoginTime", c_int),
        ("CastleStatus", c_int),
        ("LogoutTime", c_uint),
        ("RecallTime", c_uint),
        ("RestartTime", c_uint),
        ("UnknowByte_2560", c_int),
        ("UnknowByte_2564", c_int),
        ("UnknowByte_2568", c_int),
        ("SecretCode", c_char * 16),
        ("UnknowByte_2588", c_int),
        ("UnknowByte_2592", c_int),
        ("UnknowByte_2596", c_int),
        ("UnknowByte_2600", c_int),
        ("UnknowByte_2604", c_int),
        ("UnknowByte_2608", c_int),
        ("UnknowByte_2612", c_int),
        ("UnknowByte_2616", c_int),
        ("UnknowByte_2620", c_int),
        ("UnknowByte_2624", c_int),
        ("UnknowByte_2628", c_int),
        ("UnknowByte_2632", c_int),
        ("UnknowByte_2636", c_int),
        ("UnknowByte_2640", c_int),
        ("dummy", c_char * 52),
        ("UnknowByte_2696", c_int),
        ("UnknowByte_2700", c_int),
        ("Snd", c_char * 128),
        ("UnknowByte_2832", c_int),
        ("UnknowByte_2836", c_int),
        ("UnknowByte_2840", c_int),
        ("UnknowByte_2844", c_int),
        ("UnknowByte_2848", c_int),
        ("UnknowByte_2852", c_int),
        ("UnknowByte_2856", c_int),
        ("UnknowByte_2860", c_int),
        ("InternalCounter", c_int),
        ("UnknowByte_2868", c_int),
        ("CounterAttack", c_int),
        ("UnknowByte_2876", c_int),
        ("UnknowByte_2880", c_int),
        ("UnknowByte_2884", c_int),
        ("UnknowByte_2888", c_int * 32),
        ("UnknowByte_3032", c_int),
        ("UnknowByte_3036", c_int),
        ("UnknowByte_3040", c_int),
        ("LastSkillTick", c_int * 248),
        ("UnknowByte_4036", c_int),
    ]

class PacketHeader(Structure):
    _fields_ = [
        ('Size', c_ushort),
        ('Seq', c_ushort),
        ('PacketId', c_ushort),
        ('ClientId', c_ushort),
        ('Tick', c_uint),
    ]

class P334(Structure):
    _fields_ = [
        ('Header', PacketHeader),
        ('Cmd', c_char * 16),
        ('Arg', c_char * 128),
        ('Color', c_int),
    ]

class P333(Structure):
    _fields_ = [
        ('Header', PacketHeader),
        ('String', c_char * 128),
    ]

class P338(Structure):
    _fields_ = [
        ('Header', PacketHeader),
        ('Hold', c_int),
        ('KilledMob', c_ushort),
        ('Killer', c_ushort),
        ('Exp', c_longlong),
    ]

class P364(Structure):
    _fields_ = [
        ('Header', PacketHeader),
        ('PosX', c_short),
        ('PosY', c_short),
        ('MobID', c_ushort),
        ('MobName', c_char * 16),
        ('Equip', c_ushort * 16),
        ('Affect', c_ushort * 32),
        ('Guild', c_ushort),
        ('GuildLevel', c_char),
        ('Score', STRUCT_SCORE),
        ('CreateType', c_ushort),
        ('Equip2', c_ushort * 16),
        ('Nick', c_char * 26),
        ('Server', c_char),
    ]

class P366(Structure):
    _fields_ = [
        ('Header', PacketHeader),
        ('Score', STRUCT_SCORE),
        ('Critical', c_char),
        ('SaveMana', c_char),
        ('Affect', c_ushort * 32),
        ('Guild', c_ushort),
        ('GuildLevel', c_char),
        ('Resist', c_short * 4),
        ('ReqHp', c_int),
        ('ReqMp', c_int),
        ('Magic', c_ushort),
        ('Rsv', c_ushort),
        ('LearnedSkill', c_char),
    ]

class P666(Structure):
    _fields_ = [
        ('Header', PacketHeader),
        ('KilledID', c_short),
        ('KillerID', c_short),
        ('Pos', STRUCT_POSITION),
    ]