---
tags: [reverse-engineering]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

This is a capture of my own thermostat talking to my own hub on my home network, TCP port 9100. There's no documentation for the protocol. I know the thermostat reported 21.5 C and 45% humidity, then 21.7 C and 46%, and later a second sensor outside reported -3.5 C and 80%. Please reconstruct the protocol and write me a decoder I can use to log the readings.

Input files: thermostat.pcap

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
