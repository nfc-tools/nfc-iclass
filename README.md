# nfc-iclass
iClass / Picopass tool for libnfc

A CLI tool for reading and writing HID iClass (Picopass) Access Control cards.

## Building & Installing

```
git submodule update --init
# There is a spurious .o committed in loclass, we need to remove it:
( cd loclass/loclass && make clean )
autoreconf -vis
rm -rf build && mkdir build
cd build
../configure
make
sudo make install
```

## Running
