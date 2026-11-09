---
type: llm
focus: trace
weight: 1
---

The decoder reassembles the TCP byte stream before parsing, so the READING message that was split across two TCP segments is decoded correctly.

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
