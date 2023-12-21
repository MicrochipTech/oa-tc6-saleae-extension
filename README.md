# 10Base-T1x MAC-PHY Serial Interface Protocol Analyzer


## Getting started
## Analyzer Settings

### Trace

Select trace output
- transactions: Transaction relevant data (excludes dummy bytes etc.)

Not implemented options
- rx: receive data including dummy bytes
- tx: transmit data including dummy bytes
- ethernet-frames: Decoded Ethernet frames

### Block Payload Size

Block payload size used in data transactions.
- auto-detec: The analyzer will try to auto-detec the size by identifying writes to the configuration register

Not that auto-detect only works if changes to the register containing these settings are captured so that the analyzer can extract them or if the default settings do not change.

Not implemented yet
- 64: Sets block payload size to 64 bytes
- 32: Sets block payload size to 32 bytes

### Control Data Read/Write Protection

This setting defines whether or not the protection for the control read/write data is enabled.
- auto-detect: The analyzer will try to auto-detec the setting by identifying writes to the configuration register

Not that auto-detect only works if changes to the register containing these settings are captured so that the analyzer can extract them or if the default settings do not change e.g. if the capture is started after register configuration is finished and the settings are not the default the analyzer will be unable to detect the correct setting. In this case the user can manually configure the setting for the capture session.

Not implemented yet
- enabled: Enable control read/write data protection
- disabled: Disable control read/write data protection

## Limitations

When multiple registers are written/read in one transaction only the first register will be checked for updates on the configuration settings

In auto-detect mode the analyzer will check for writes to the CONFIG_0 register in oder to detect changes to the following settings:
- Control Read/Write Data Protection
- Block Payload Size

If these settings change the analyzer will use these for decoding. However, if changes to these registers are done before capturing the data the analyzer will not be able to decode properly. In this case the user should manually configure the settings with the expected values.
