# r2cLEMENCy

DEF CON 25 CTF Finals, organized by Legitimate Business Syndicate, used a brand new architecture called [cLEMENCy](https://github.com/legitbs/cLEMENCy). It features many bizarre designs:

* 9-bit bytes (referred as nytes)
* 27-bit general-purpose registers
* Middle-endian
  + A word of 2 nytes is represented as `a[1] << 9 | a[0]`
  + A word of 3 nytes is represented as `a[1] << 27 | a[2] << 18 | a[0]`
* Variable length instructions (18,27,36,54 bits) which are serialized in middle-endian. Opcodes are between 5 bits and 18 bits.

Memory mappings:

```
[0000000,4000000) Main Program Memory
[4000000,400001e) Clock IO
[4010000,4011000) Flag IO
[5000000,5002000) Data Received
[5002000,5002003) Data Received Size
[5010000,5012000) Data Sent
[5012000,5012003) Data Sent Size
[5100000,5104000) NFO file
[7ffff00,7ffff1c) Interrupt Pointers
[7ffff80,8000000) Processor Identification and Features
```

This repository contains a bunch of radare2 plugins for cLEMENCy.

## Building

This repository can be built either standalone or as a subdirectory of radare2-extras.

### Standalone

Specify `PKG_CONFIG_PATH` if you install radare2 to a user directory.

```zsh
# cd clemency
PKG_CONFIG_PATH=~/.config/radare2/prefix/lib/pkgconfig make
```

### Subdirectory of radare2-extras

```zsh
(cd ..  # cd radare2-extras
./configure --prefix=~/.config/radare2/prefix  # generates options.mk
)
make
```

`make info` to see used environment variables.

## Installation

* `make symstall`: install symlinks to `R2PM_PLUGDIR` and `R2PM_SHAREDIR`
* `make install`: install files

## Usage

[DEF CON CTF 2017 Final Scores and Data Dumps](https://blog.legitbs.net/2017/07/def-con-ctf-2017-final-scores-and-data.html)

`DEF CON 25 CTF Finals service binaries/` contains service binaries used in DEF CON CTF Finals.

```zsh
r2 -e asm.parser=clcy -e asm.midflags=1 -a clcy clcy:///tmp/babyecho
```

## Components

* `io/io_clcy.c`: expands 9-bit to 16-bit and unexpands 16-bit when closing
* `core/core_clcy.c`: hexdump commands tailored to 9-bit
* `bin/bin_clcy.c`: creates sections for cLEMENCy memory mappings, and sets up the NFO section
* `asm/asm_clcy.c`: disassembler and assembler. `include/opcode-inc.h` is taken from https://github.com/pwning/defcon25-public by Plaid Parliament of Pwning
* `anal/anal_clcy.c`: instruction classifier and ESIL translator
* `parse/parse_clcy.c`: C-like pseudo disassembler and variable substituter

![](https://ptpb.pw/XeC6.jpg)
