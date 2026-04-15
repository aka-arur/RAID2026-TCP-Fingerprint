# OT Device PCAP Captures

Five network captures from physical OT devices deployed in a power systems laboratory. Three devices run Modbus/TCP; two run OPC UA. All are off-the-shelf hardware polled via custom in-house driver software on embedded Linux PCs. The request-side stack is non-standard — do not use these captures to study Modbus master or OPC UA client behavior. The device-side reply stack is hardware-native and suitable for transport-layer analysis.

## Captures

| File | Device | Protocol | Application |
|---|---|---|---|
| `deif_mic2.pcap` | DEIF MIC-II multi-instrument | Modbus/TCP | Substation measurement |
| `fronius_symo.pcap` | Fronius SYMO inverter | Modbus/TCP | PV inverter |
| `phoenix_evse.pcap` | Phoenix Contact UM-EN-EV | Modbus/TCP | EV charger |
| `plcnext.pcap` | Phoenix Contact PLCNext | OPC UA | 22 kW electric boiler controller |
| `siemens_s7.pcap` | Siemens S7 | OPC UA | Vanadium redox-flow battery management |

## Collection notes

- Polling software: custom in-house code on embedded Linux PCs
- The master/client side does not represent a typical PLC environment
- Device-side TCP behavior is hardware-inherited, reflecting physical memory and real-time constraints of the embedded implementation

## Usage

These captures serve as a ground-truth validation set for transport-layer OT device fingerprinting. Applying $F_\text{TCP}$ to all five captures yields zero flagged addresses — every device's TCP window sizes fall within the bounds defined for conformant OT hardware.
