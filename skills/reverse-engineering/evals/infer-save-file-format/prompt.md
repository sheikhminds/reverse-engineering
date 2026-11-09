---
tags: [reverse-engineering]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

I've got four save files from an old game I used to play, and the game is long gone. There's no documentation anywhere. Here's what I know about them: empty.sav is a brand new game with no characters. one-player.sav has one character, Ann, level 5, 87.5 HP, 1200 gold. one-player-later.sav is the same game later on: Ann is level 6, 100 HP, 1350 gold. two-players.sav adds a second character, Boris, level 2, 42.25 HP, 75 gold. I'd like to read these in Python and ideally write new ones too. Can you work out the format, write me a spec, and give me a parser I can trust?

Input files: empty.sav, one-player.sav, one-player-later.sav, two-players.sav

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
