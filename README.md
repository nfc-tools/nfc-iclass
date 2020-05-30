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

Default behaviour is to dump APP1.

For more options:
```
nfc-iclass -h

Usage: ./src/nfc-iclass [options] [BINARY FILE|HEX DATA]

  Options:

	-c <KEY>      Use CREDIT KEY Kc / APP2 (default is DEBIT KEY Kd / APP1)
	-C <?|CARD>   Create CONFIG card (? prints list of config cards)
	-d <KEY>      Use non-default DEBIT KEY for APP1
	-e            AUTH KEY is ELITE
	-h            You're looking at it
	-k <KEY>      Keyroll KEY for CONFIG card
	-n            Do not DIVERSIFY key
	-o <FILE>     Write TAG data to FILE
	-r <KEY>      Re-Key with KEY (assumes new key is ELITE)
	-R <KEY>      Re-Key to non-ELITE
	-w <BLOCK>    WRITE to tag starting from BLOCK (specify # in HEX)

	If no KEY is specified, default HID Kd (APP1) will be used

### Examples

Use ELITE key for APP1:

```
	nfc-iclass -d DEADBEEFCAFEF00D -e
```
Dump contents of APP2:

```
	nfc-iclass -c 0DC442031337D00F
```
Write APP1 blocks 8 & 9:

```
	nfc-iclass -w 8 aabbccddaabbccddaabbccddaabbccdd
```
or

```
	nfc-iclass -w 8 /tmp/iclass-8-9-dump.icd
```
Re-key to ELITE key:
```
        nfc-iclass -r deadbeefcafef00d
```
Revert to default iClass Kd (note re-key to NON-ELITE with -R)
```
        nfc-iclass -d deadbeefcafef00d -e -R AFA785A7DAB33378
```
Show available CONFIG cards:

```
        nfc-iclass -C ?
```
Create CONFIG card AV1:

```
        nfc-iclass -C AV1
```
Create KEYROLL card:
```
        nfc-iclass -C KRE -k F00FBEEBD00BEEEE
```

### Config cards

iClass readers can be reconfigured using CONFIG cards. These will normally be provided free of charge
upon request but as we now have the master Kd it's easy enough to dump the set and recreate them at will.

The available cards are:

*		AV1:	Audio/Visual #1 - Beep ON, LED Off, Flash GREEN on read
*		AV2:	Audio/Visual #2 - Beep ON, LED RED, Host must flash GREEN
*		AV3:	Audio/Visual #3 - Beep ON, LED Off, Host must flash RED and/or GREEN
*		KP1:	Keypad Output #1 - Buffer ONE key (8 bit Dorado)
*		KP2:	Keypad Output #2 - Buffer ONE to FIVE kets (standard 26 bit)
*		KP3:	Keypad Output #3 - Local PIN verify
*		CSN1:	Mifare CSN #1 - 32 bit reverse output
*		CSN2:	Mifare CSN #2 - 16 bit output
*		CSN3:	Mifare CSN #3 - 34 bit output
*		KRD:	Keyroll DISABLE - Set ELITE Key and DISABLE Keyrolling
*		KRE:	Keyroll ENABLE - Set ELITE Key and ENABLE Keyrolling
*		RSTR:	Reset READER - Reset READER to defaults
*		RSTE:	Reset ENROLLER - Reset ENROLLER to defaults

*Note that a config card is slightly different from a standard one in that APP1 uses more blocks. This matters
for KEYROLL cards as they need the extra space to store the new keys. Other types may work on a standard card
but the most reliable method is to use an existing config card and overwrite it.*

