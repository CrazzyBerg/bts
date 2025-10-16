# YateBTS 2025

Everything to build and run the latest Yate + YateBTS + bladeRF xA4 for an old GSM/GPRS 2G base station.

Yate 6.4.1 and YateBTS 6.1.1 use the latest bladeRF firmware and FPGA (tested with 2.4.0 and 0.15.3).

## Bias Tee Support

The YateBTS now supports bias tee for both TX (bladeRF BT-100) and RX (bladeRF BT-200).
To enable this feature, update the following settings in `/usr/local/etc/yate/ybladerf.conf`:
- `tx_bias_tee=`: Set to `yes` to enable TX bias tee.
- `rx_bias_tee=`: Set to `yes` to enable RX bias tee.

## Documentation Links

For more detailed tuning and configuration guidance, refer to the following documentation:
- [ARFCN Tuning Guide](arfcn_tune.md)
- [Advanced Tuning Guide](advanced_tune.md)

## Tested (recommended) Build Environment

- **Raspberry Pi 5**
- **bladeRF 2.0 micro xA4**
- **Raspberry Pi OS Bookworm (64-bit Lite)** (based on Debian 12 Bookworm), **GCC-11/GCC-12**, **Apache2**, **PHP 8.2 (backwards compatible with PHP 5.6)**
> **_⚠️ WARNING:_ At least for Raspberry Pi 5 I do not recommend desktop image! Lite only as on desktop image IQ samples become negative in short time!**

## Installation Instructions

Clone the repository and run `install.sh` as a user; you will be prompted for your sudo password at some point.
Compilation takes approximately 10-15 minutes on a Raspberry Pi 5. The script will install all dependencies, compile sources, and install Apache2 + PHP (if you choose the NiPC web interface).

### Post-Installation Information

- **YateBTS Configuration:**
  - The base configuration is set for the 900 MHz band, with MCC=001 and MNC=01.
  - IMSI regex starts with `00101`.

- **To start the Yate service:**
  ```bash
  sudo yate -s
  ```

- **To connect to YateBTS via telnet:**
  ```bash
  telnet localhost 5038
  ```

- **If Apache2 and PHP were installed, access the NiPC web application:**
  ```
  http://{your_local_IP_or_name}/nipc/main.php
  ```

- **David's phone number for audio and echo test:** `32843`
- **Send an SMS to the Eliza chatbot:** `35492`

- **If you flashed the SIM with the pySim example, your assigned phone number is** `10000551`.

### Example Usage of pySim

Here is an example usage of pySim (this can be used to program your first SIM):

```bash
./pySim-prog.py -p 0 -n YateBTS -c 1 -x 310 -y 260 -i 310260000000551 -s 8912600000000005512 -o 659BDA03311ACBBE767CB56D565A58D6 -k BA351F5C4690491D86377319E5A6DBCC
```
