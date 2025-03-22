# NTPddos

**WARNING!!!**  
Conducting DDOS attacks on other devices or networks is **ILLEGAL**! This project is provided **ONLY for study and research purposes**. Any illegal use of this project is solely the responsibility of the user. The project author is not associated with any illegal activities resulting from the misuse of this tool.

## Overview

NTPddos is a tool that exploits NTP servers using the monlist request and IP forgery techniques to perform a type of DDOS attack. This project is intended for educational and research purposes only.

## Requirements

- **Python:** 3.9
- **Dependencies:** See [requirements.txt](requirements.txt) for the list of required packages.
- **Npcap:** Install Npcap (required for Scapy) from [https://npcap.com/#download](https://npcap.com/#download)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/LanYangYang321/NTPddos.git
   ```
2. Navigate to the project directory:
   ```bash
   cd NTPddos
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the DDOS Tool

Use Python 3.9 to run the tool. You can execute the main script as follows:
```bash
python attacker.py
```

For creating an executable with a UI:
```bash
pyinstaller -F -w -i icon.ico attacker.py
```

### Scanning for Available Monlist NTP Servers

To scan for available NTP servers supporting the monlist request, run:
```bash
python scanner.py
```

## Explanatory Videos

For more details and a demonstration, please watch the following videos:

- [YouTube Video](https://www.youtube.com/watch?v=OQKr6GtSTp8)
- [Bilibili Video](https://www.bilibili.com/video/BV15vS3YpEt8)

## Legal Disclaimer

This project is intended for educational and research purposes only. The author is not responsible for any misuse of this code. Users must bear all legal consequences and risks arising from any illegal activities performed using this tool.

## License

This project is licensed under the MIT License.
