# QUANTUMSTRAND

QUANTUMSTRAND is an experiment that augments traditional `strings.exe` output with context to aid in malware analysis and reverse engineering.
For example, we show the structure of a file alongside its strings and mute/highlight entries based on their global prevalence, library association, expert rules, and more.
If the experiment proves successful, we'll merge the best features directly into FLOSS and deprecate the QUANTUMSTRAND codename.

You can get prerelease builds of QUANTUMSTRAND from the [releases page](https://github.com/mandiant/flare-floss/releases).
Of course, this is an experiment, so there are no guarantees and many things yet to polish.

## Features

  - extract ASCII and UTF-16LE strings
  - show strings next to right-aligned, colored context, including "tags" and file offset
  - render string within PE section range delimiters
  - annotate strings from known PE structures, like the import table
  - don't show junk strings that overlap with instructions
  - mute strings known to be globally prevalent, via an embedded database
  - mute strings from popular open source libraries, via embedded databases
  - highlight strings that match expert rules, via embedded databases


![screenshot 1](https://github.com/mandiant/flare-floss/assets/156560/ed7fb658-742b-40f8-87f5-a2674d7db3c0)
![screenshot 2](https://github.com/mandiant/flare-floss/assets/156560/65a1429a-e538-4154-8474-c4de7f2d2df1)