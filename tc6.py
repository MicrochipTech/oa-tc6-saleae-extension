from enum import Enum

class Tc6State(Enum):
    CHIP_DESELECT = 0
    HEADER_START = 1
    HEADER = 2

    CTRL_READ_HEADER_ECHO = 3
    CTRL_READ_DATA = 4
    CTRL_READ_DUMMY_BYTES = 5

    CTRL_WRITE_HEADER_ECHO = 6
    CTRL_WRITE_DATA_ECHO = 7
    CTRL_WRITE_DUMMY_BYTES = 8
    ERROR = 9
    DATA_TRANSACTION = 10
    FOOTER = 11

class Tc6Header():
    DNC_MASK = 0x80000000
    @classmethod
    def from_bytes(cls, header):
        if isinstance(header, (bytes, bytearray)):
            header = int.from_bytes(header, byteorder="big")
        elif isinstance(header, int):
            pass
        else:
            raise TypeError()

        if header & cls.DNC_MASK:
            hdr = Tc6TransmitDataHeader.from_bytes(header)
        else:
            hdr = Tc6ControlCommandHeader.from_bytes(header)
        return hdr

class Tc6DataFooter():
    EXST_MASK = 0x80000000
    HDRB_MASK = 0x40000000
    SYNC_MASK = 0x20000000
    RCA_MASK = 0x1f000000
    RCA_POS = 24
    VS_MASK = 0x00c00000
    VS_POS = 22
    DV_MASK = 0x00200000
    SV_MASK = 0x00100000
    SWO_MASK = 0x000f0000
    SWO_POS = 16
    FD_MASK = 0x00008000
    EV_MASK = 0x00004000
    EBO_MASK = 0x00003f00
    EBO_POS = 8
    RTSA_MASK = 0x00000080
    RTSP_MASK = 0x00000040
    TXC_MASK = 0x0000003e
    TXC_POS = 1
    PARITY_MASK = 0x00000001

    def __init__(self, exst, hdrb, sync, rca, vs, dv, sv, swo, fd, ev, ebo, rtsa, rtsp, txc, parity):
        self.exst = exst
        self.hdrb = hdrb
        self.sync = sync
        self.rca = rca
        self.vs = vs
        self.dv  = dv
        self.sv = sv
        self.swo = swo
        self.fd = fd
        self.ev = ev
        self.ebo = ebo
        self.rtsa = rtsa
        self.rtsp = rtsp
        self.txc = txc
        self.parity = parity

    @classmethod
    def from_bytes(cls, footer):
        try:
            if isinstance(footer, (bytes, bytearray)):
                footer = int.from_bytes(footer, byteorder="big")
            elif isinstance(footer, int):
                pass
            else:
                raise TypeError()
            values = cls.decode_footer(footer)
        except ValueError:
            pass
        return cls(*values)

    @classmethod
    def decode_footer(cls, footer):
        exst =  True if footer & cls.EXST_MASK else False
        hdrb = True if footer & cls.HDRB_MASK else False
        sync = True if footer & cls.SYNC_MASK else False
        rca = (footer & cls.RCA_MASK) >> cls.RCA_POS
        vs = (footer & cls.VS_MASK) >> cls.VS_POS
        dv = True if footer & cls.DV_MASK else False
        sv = True if footer & cls.SV_MASK else False
        swo = (footer & cls.SWO_MASK) >> cls.SWO_POS
        fd = True if footer & cls.FD_MASK else False
        ev = True if footer & cls.EV_MASK else False
        ebo = (footer & cls.EBO_MASK) >> cls.EBO_POS
        rtsa = True if footer & cls.RTSA_MASK else False
        rtsp = True if footer & cls.RTSP_MASK else False
        txc = (footer & cls.TXC_MASK) >> cls.TXC_POS
        parity = True if footer & cls.PARITY_MASK else False
        # TODO: parity check
        return (exst, hdrb, sync, rca, vs, dv, sv, swo, fd, ev, ebo, rtsa, rtsp, txc, parity)

class Tc6TransmitDataHeader():
    DNC_MASK = 0x80000000
    SEQ_MASK = 0x40000000
    NORX_MASK = 0x20000000
    RSVD1_MASK = 0x1f000000
    RSVD1_POS = 24
    VS_MASK = 0x00c00000
    VS_POS = 22
    DV_MASK = 0x00200000
    SV_MASK = 0x00100000
    SWO_MASK = 0x000f0000
    SWO_POS = 16
    EV_MASK = 0x00004000
    EBO_MASK = 0x00003f00
    EBO_POS = 8
    TSC_MASK = 0x000000c0
    TSC_POS = 6
    RSVD2_MASK = 0x0000003e
    RSVD2_POS = 1
    PARITY_MASK = 0x00000001

    def __init__(self, dnc, seq, norx, vs, dv, sv, swo, ev, ebo, tsc, p):
        self.dnc = dnc
        self.seq = seq
        self.norx = norx
        self.vs = vs
        self.dv = dv
        self.sv = sv
        self.swo = swo
        self.ev = ev
        self.ebo = ebo
        self.tsc = tsc
        self.p = p

    @classmethod
    def from_bytes(cls, header):
        try:
            if isinstance(header, (bytes, bytearray)):
                header = int.from_bytes(header, byteorder="big")
            elif isinstance(header, int):
                pass
            else:
                raise TypeError()
            values = cls.decode_header(header)
        except ValueError:
            pass
        return cls(*values)

    @classmethod
    def decode_header(cls, header):
        dnc =  True if header & cls.DNC_MASK else False
        seq = True if header & cls.SEQ_MASK else False
        norx = True if header & cls.NORX_MASK else False
        vs = (header & cls.VS_MASK) >> cls.VS_POS
        dv = True if header & cls.DV_MASK else False
        sv = True if header & cls.SV_MASK else False
        swo = (header & cls.SWO_MASK) >> cls.SWO_POS
        ev = True if header & cls.EV_MASK else False
        ebo = (header & cls.EBO_MASK) >> cls.EBO_POS
        tsc = (header & cls.TSC_MASK) >> cls.TSC_POS
        p = True if header & cls.PARITY_MASK else False
        # TODO: parity check
        return (dnc, seq, norx, vs, dv, sv, swo, ev, ebo, tsc, p)

class Tc6ControlCommandHeader():
    DNC_MASK = 0x80000000
    HDRB_MASK = 0x40000000
    WNR_MASK = 0x20000000
    AID_MASK = 0x10000000
    MMS_MASK = 0x0f000000
    MMS_POS = 24
    ADDR_MASK = 0x00ffff00
    ADDR_POS = 8
    LEN_MASK = 0x000000fe
    LEN_POS = 1
    PARITY_MASK = 0x00000001

    def __init__(self, dnc, wnr, hdrb, aid, mms, addr, len, p):
        self.dnc = dnc
        self.wnr = wnr
        self.hdrb = hdrb
        self.aid = aid
        self.mms = mms
        self.addr = addr
        self.len = len
        self.p = p

    @classmethod
    def from_bytes(cls, header):
        try:
            if isinstance(header, (bytes, bytearray)):
                header = int.from_bytes(header, byteorder="big")
            elif isinstance(header, int):
                pass
            else:
                raise TypeError()
            values = cls.decode_header(header)
        except ValueError:
            pass
        return cls(*values)

    @classmethod
    def decode_header(cls, header):
        dnc =  True if header & cls.DNC_MASK else False
        wnr = True if header & cls.WNR_MASK else False
        hdrb = True if header & cls.HDRB_MASK else False
        aid = True if header & cls.AID_MASK else False
        mms = (header & cls.MMS_MASK) >> cls.MMS_POS
        addr = (header & cls.ADDR_MASK) >> cls.ADDR_POS
        len = (header & cls.LEN_MASK) >> cls.LEN_POS
        p = True if header & cls.PARITY_MASK else False
        # TODO: parity check
        return (dnc, wnr, hdrb, aid, mms, addr, len, p)
