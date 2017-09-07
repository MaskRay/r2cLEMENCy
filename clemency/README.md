# r2cLEMENCy

## Building

This repository can be built either standalone or as a subdirectory of radare2-extras.

### Standalone

```zsh
PKG_CONFIG_PATH=~/.config/radare2/prefix/lib/pkgconfig make
```

### Subdirectory of radare2-extras

```zsh
(cd ..  # radare2-extras
./configure --prefix=~/.config/radare2/prefix  # generates options.mk
)
make
```

`make info` to see used environment variables.

Installation
------------

* `make symstall`: install symlinks to `R2PM_PLUGDIR` and `R2PM_SHAREDIR`
* `make install`: install files
