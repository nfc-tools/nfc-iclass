# nfc-iclass
iClass / Picopass tool for libnfc

A CLI tool for reading and writing HID iClass (Picopass) Access Control cards.

## Building & Installing

```
git submodule update --init
autoreconf -vis
rm -rf build && mkdir build
cd build
../configure
make
sudo make install
```

## Running

### Examples

