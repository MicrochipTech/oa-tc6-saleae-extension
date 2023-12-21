# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum
from collections import deque

class Tc6State(Enum):
    HEADER_START = 0
    CHIP_DESELECT = 1
    HEADER = 2
    CTRL_READ_TRANSACTION_HEADER_ECHO = 3
    CTRL_READ_TRANSACTION_DATA = 4
    CTRL_WRITE_TRANSACTION_DATA = 5
    CTRL_WRITE_TRANSACTION_DUMMY_BYTES = 6
    ERROR = 7
    DATA_TRANSACTION = 8

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

def create_control_transaction_frame(header: Tc6ControlCommandHeader, data: bytearray, protected, start_time, end_time):
    if header.wnr:
        text = "Control Wrtie Transaction: "
    else:
        text = "Control Read Transaction: "
    text += f"MMS={header.mms} ADDR={hex(header.addr)} LEN={header.len} "
    text += "DATA=0x"
    for i in range(len(data) // 4):
        if protected and i % 2:
            pass # drop data protection bytes
        else:
            text += f"{data[i * 4:i * 4 + 4].hex()}_"
    text = text[:-1] # remove trailing underscore
    return AnalyzerFrame('analyzer_frame', start_time, end_time, {'labelText': text})

def create_data_transaction_frame(header: Tc6TransmitDataHeader, data: bytearray, start_time, end_time):
    text = f"Data Transaction: (Header: SEQ={header.seq} NORX={hex(header.norx)} DV={header.dv} ...) "
    text += f"(Data=0x{data[:4].hex()}...)"
    footer = Tc6DataFooter.from_bytes(data[-4:])
    text += f"(Footer: EXST={footer.exst} HDRB={footer.hdrb} SYNC={footer.sync} RCA={footer.rca} VS={footer.vs} DV={footer.dv} SV={footer.sv} SWO={footer.swo} "
    text += f"FD={footer.fd} EV={footer.ev} EBO={footer.ebo} RTSA={footer.rtsa} RTSP={footer.rtsp} TXC={footer.txc} PARITY={footer.parity})"
    return AnalyzerFrame('analyzer_frame', start_time, end_time, {'labelText': text})


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    block_payload_size_setting = ChoicesSetting(choices=('auto-detect', '64', '32'))
    control_data_protection_setting = ChoicesSetting(choices=('auto-detect', 'enabled', 'disabled'))
    trace_setting = ChoicesSetting(choices=('transactions', 'tx', 'rx', 'ethernet-frames'))

    result_types = {
        'analyzer_frame': {
            'format': '{{data.labelText}}'
        },
        'receive_data': {
            'format': '{{data.values}}'
        }
    }  

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.state = Tc6State.CHIP_DESELECT
        self.header_start = 0
        self.header_end = 0
        self.transaction_start = 0
        self.transaction_end = 0
        self.txbuf = bytearray()
        self.rxbuf = bytearray()

        self.chunk_size = 64
        self.ctrl_rw_data_protection = False
        self.transaction_trace = True
    
    def decode(self, frame: AnalyzerFrame):
        return_frame = None
        if frame.type == "disable":
            self.state = Tc6State.CHIP_DESELECT

        elif frame.type == "enable":
            self.txbuf.clear()
            self.rxbuf.clear()
            self.state = Tc6State.HEADER_START

        elif frame.type == "result":
            self.txbuf.extend(frame.data["mosi"])
            self.rxbuf.extend(frame.data["miso"])

            if self.state == Tc6State.HEADER_START:
                self.transaction_start = frame.start_time
                self.header_start = frame.start_time
                self.state = Tc6State.HEADER

            elif self.state == Tc6State.HEADER:
                if len(self.txbuf) == 4:
                    self.header = Tc6Header.from_bytes(self.txbuf)
                    self.header_end = frame.end_time
                    if isinstance(self.header, Tc6ControlCommandHeader):
                        if self.header.wnr:
                            self.state = Tc6State.CTRL_WRITE_TRANSACTION_DATA
                        else:
                            self.state = Tc6State.CTRL_READ_TRANSACTION_HEADER_ECHO
                        self.rxbuf.clear() # remove rx dummy bytes
                    else:
                        self.state = Tc6State.DATA_TRANSACTION
                    self.txbuf.clear()

            elif self.state == Tc6State.CTRL_WRITE_TRANSACTION_DATA:
                if len(self.txbuf) == (self.header.len + 1) * 4 * (2 if self.ctrl_rw_data_protection else 1):
                    self.txdata = bytearray(self.txbuf)
                    self.txbuf.clear()
                    self.state = Tc6State.CTRL_WRITE_TRANSACTION_DUMMY_BYTES

            elif self.state == Tc6State.CTRL_WRITE_TRANSACTION_DUMMY_BYTES:
                if len(self.txbuf) == 4:
                    self.transaction_end = frame.end_time
                    # TODO: we only support single register write here so we would miss updates when multiple registers are written by addess auto increment
                    self.check_transaction_parameter_change()
                    if self.transaction_trace:
                        return_frame = create_control_transaction_frame(self.header, self.txdata, self.ctrl_rw_data_protection, self.transaction_start, self.transaction_end)
                    self.txbuf.clear()
                    self.rxbuf.clear()
                    self.state = Tc6State.HEADER_START

            elif self.state == Tc6State.CTRL_READ_TRANSACTION_HEADER_ECHO:
                if len(self.txbuf) == 4:
                    self.rxbuf.clear()
                    self.state = Tc6State.CTRL_READ_TRANSACTION_DATA

            elif self.state == Tc6State.CTRL_READ_TRANSACTION_DATA:
                if len(self.rxbuf) == (self.header.len + 1) * 4 * (2 if self.ctrl_rw_data_protection else 1):
                    self.transaction_end = frame.end_time
                    if self.transaction_trace:
                        return_frame = create_control_transaction_frame(self.header, self.rxbuf, self.ctrl_rw_data_protection, self.transaction_start, self.transaction_end)
                    self.txbuf.clear()
                    self.rxbuf.clear()
                    self.state = Tc6State.HEADER_START

            elif self.state == Tc6State.DATA_TRANSACTION:
                if len(self.txbuf) == self.chunk_size:
                    self.transaction_end = frame.end_time
                    if self.transaction_trace:
                        return_frame = create_data_transaction_frame(self.header, self.rxbuf, self.transaction_start, self.transaction_end)
                    self.txbuf.clear()
                    self.rxbuf.clear()
                    self.state = Tc6State.HEADER_START
        if return_frame:
            return return_frame

    def check_transaction_parameter_change(self):
        # Let's see if there is a change in control data protection mode
        if self.header.mms == 0 and self.header.addr == 0x4:
            reg = int.from_bytes(self.txdata[:4], byteorder="big")
            if reg & 0x00000020:
                if not self.ctrl_rw_data_protection:
                    print("Control Data R/W protection changed to enabled")
                self.ctrl_rw_data_protection = True
            else:
                if self.ctrl_rw_data_protection:
                    print("Control Data R/W protection changed to disabled")
                self.ctrl_rw_data_protection = False
            block_payload_size = reg & 0x00000007
            if block_payload_size == 0b101:
                self.chunk_size = 32
            elif block_payload_size == 0b110:
                self.chunk_size = 64

