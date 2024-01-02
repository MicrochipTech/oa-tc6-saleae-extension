# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum
#import imp
#from pathlib import Path
#packages = imp.load_source('packages', str(Path(__file__).parent / "tc6.py"))
from tc6 import Tc6ControlCommandHeader, Tc6Header, Tc6State, Tc6DataFooter, Tc6TransmitDataHeader

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

def create_rx_discard_data_frame(data, start_time, end_time):
    text = f"Chunk data discard: 0x{data.hex()}"
    return AnalyzerFrame('analyzer_frame', start_time, end_time, {'labelText': text})

def create_rx_header_echo_frame(data, start_time, end_time):
    header = Tc6ControlCommandHeader.from_bytes(data)
    text = f"Echoed Control Header: "
    text += f"DNC={header.dnc} HDRB={header.hdrb} WNR={header.wnr} AID={header.aid} MMS={header.mms} ADDR={hex(header.addr)} LEN={header.len} P={header.p}"
    return AnalyzerFrame('analyzer_frame', start_time, end_time, {'labelText': text})

def create_rx_control_data_echo_frame(data, start_time, end_time):
    text = f"Echoed Data: 0x{data.hex()}"
    return AnalyzerFrame('analyzer_frame', start_time, end_time, {'labelText': text})

def create_control_header_frame(header, start_time, end_time):
    text = f"Control Header: "
    text += f"DNC={header.dnc} HDRB={header.hdrb} WNR={header.wnr} AID={header.aid} MMS={header.mms} ADDR={hex(header.addr)} LEN={header.len} P={header.p}"
    return AnalyzerFrame('analyzer_frame', start_time, end_time, {'labelText': text})

class Trace(Enum):
    TRANSACTION = 0
    RX = 1
    TX = 2
    ETHERNET_FRAME = 3

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    block_payload_size_setting = ChoicesSetting(choices=('auto-detect', '64', '32'))
    control_data_protection_setting = ChoicesSetting(choices=('auto-detect', 'enabled', 'disabled'))
    trace_setting = ChoicesSetting(choices=('transactions', 'tx', 'rx', 'ethernet-frames'))

    result_types = {
        'analyzer_frame': {
            'format': '{{data.labelText}}'
        }
    }  

    def __init__(self):
        """High level analyzer intitialization
        """
        self.state = Tc6State.CHIP_DESELECT
        self.header_start = 0
        self.header_end = 0
        self.header_echo_end = None
        self.transaction_start = 0
        self.transaction_end = 0
        self.txbuf = bytearray()
        self.rxbuf = bytearray()

        self.chunk_size = 64
        self.ctrl_rw_data_protection = False
        if self.trace_setting == "transactions":
            self.trace = Trace.TRANSACTION
        elif self.trace_setting == "rx":
            self.trace = Trace.RX
        elif self.trace_setting == "tx":
            self.trace = Trace.TX
        elif self.trace_setting == "ethernet-frame":
            self.trace = Trace.ETHERNET_FRAME
    
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
                            self.state = Tc6State.CTRL_WRITE_HEADER_ECHO
                        else:
                            self.state = Tc6State.CTRL_READ_HEADER_ECHO
                        if self.trace == Trace.RX:
                            return_frame = create_rx_discard_data_frame(self.rxbuf, self.header_start, self.header_end)
                        elif self.trace == Trace.TX:
                            return_frame = create_control_header_frame()
                        self.rxbuf.clear() # remove rx dummy bytes
                    else:
                        self.state = Tc6State.DATA_TRANSACTION
                    self.txbuf.clear()

            elif self.state == Tc6State.CTRL_WRITE_HEADER_ECHO:
                if len(self.txbuf) == 1:
                    self.header_echo_start = frame.start_time
                elif len(self.txbuf) == 4:
                    self.header_echo_end = frame.end_time
                    if self.trace == Trace.RX:
                        return_frame = create_rx_header_echo_frame(self.rxbuf, self.header_echo_start, self.header_echo_end)
                    self.rxbuf.clear()
                    if (self.header.len + 1) * 4 * (2 if self.ctrl_rw_data_protection else 1) == 4:
                        self.txdata = bytearray(self.txbuf)
                        self.txbuf.clear()
                        self.rx_control_data_echo_start = None
                        self.state = Tc6State.CTRL_WRITE_DUMMY_BYTES
                    else:
                        self.state = Tc6State.CTRL_WRITE_DATA_ECHO

            elif self.state == Tc6State.CTRL_WRITE_DATA_ECHO:
                if len(self.rxbuf) == 1:
                    self.rx_control_data_echo_start = frame.start_time
                if len(self.txbuf) == (self.header.len + 1) * 4 * (2 if self.ctrl_rw_data_protection else 1):
                    self.txdata = bytearray(self.txbuf)
                    self.txbuf.clear()
                    self.state = Tc6State.CTRL_WRITE_DUMMY_BYTES

            elif self.state == Tc6State.CTRL_WRITE_DUMMY_BYTES:
                if (len(self.txbuf) == 1) and (self.rx_control_data_echo_start == None):
                    self.rx_control_data_echo_start = frame.start_time
                if len(self.txbuf) == 4:
                    self.transaction_end = frame.end_time
                    # TODO: we only support single register write here so we would miss updates when multiple registers are written by addess auto increment
                    self.check_transaction_parameter_change()
                    if self.trace == Trace.TRANSACTION:
                        return_frame = create_control_transaction_frame(self.header, self.txdata, self.ctrl_rw_data_protection, self.transaction_start, self.transaction_end)
                    elif self.trace == Trace.RX:
                        return_frame = create_rx_control_data_echo_frame(self.rxbuf, self.rx_control_data_echo_start, self.transaction_end)
                    self.txbuf.clear()
                    self.rxbuf.clear()
                    self.state = Tc6State.HEADER_START

            elif self.state == Tc6State.CTRL_READ_HEADER_ECHO:
                if len(self.txbuf) == 4:
                    self.rxbuf.clear()
                    self.state = Tc6State.CTRL_READ_DATA

            elif self.state == Tc6State.CTRL_READ_DATA:
                if len(self.rxbuf) == (self.header.len + 1) * 4 * (2 if self.ctrl_rw_data_protection else 1):
                    self.transaction_end = frame.end_time
                    if self.trace == Trace.TRANSACTION:
                        return_frame = create_control_transaction_frame(self.header, self.rxbuf, self.ctrl_rw_data_protection, self.transaction_start, self.transaction_end)
                    self.txbuf.clear()
                    self.rxbuf.clear()
                    self.state = Tc6State.HEADER_START

            elif self.state == Tc6State.DATA_TRANSACTION:
                if len(self.txbuf) == self.chunk_size:
                    self.transaction_end = frame.end_time
                    if self.trace == Trace.TRANSACTION:
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

