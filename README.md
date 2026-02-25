# NetCheck (Lean)

NetCheck is a lightweight Windows-friendly network preflight tool that maintains a persistent device inventory CSV.

It is designed for IT help desk workflows involving:

- Network printers (JetDirect / IPP / Web UI)
- 3D printers (OctoPrint)
- Servers and switches (SSH / HTTPS / Telnet)

---

## Features

- DNS resolution (forward + reverse lookup)
- ICMP ping reachability check
- TCP port connectivity checks
- Persistent inventory CSV:
  - Adds new devices automatically
  - Updates existing devices
  - Tracks `first_seen` and `last_checked`
  - Sorts most recently checked devices at the top
- Atomic file writes (prevents CSV corruption)

---

## Installation

Requires Python 3.9+

Clone the repository:

```powershell
git clone https://github.com/YOUR_USERNAME/netcheck.git
cd netcheck