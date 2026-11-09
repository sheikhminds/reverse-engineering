---
type: llm
focus: trace
weight: 1
---

The spec identifies HELLO (0x01) carrying the device id THERM-7F3A, HELLO_ACK (0x02) with a session id and a 30 second interval, READING (0x10) with sensor id, temperature as signed 16-bit tenths of a degree, humidity, and a 32-bit Unix timestamp, ACK (0x11) with the acknowledged sequence number, PING (0x20), PONG (0x21) and BYE (0x7F).

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
