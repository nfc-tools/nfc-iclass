/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2020      Adam Laurie
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */
/**
 * @file iclass.c
 * @brief provide samples structs and functions to manipulate HID iClass (Picopass) tags using libnfc
 */
#include "iclass.h"

// loclass includes
#include "ikeys.h"
#include "cipherutils.h"
#include "cipher.h"

// system
#include <stdio.h> 
#include <string.h>
#include <nfc/nfc.h>
#include <stdlib.h>

static const nfc_modulation nmiClass = {
  .nmt = NMT_ISO14443BICLASS,
  .nbr = NBR_106,
};

static const nfc_modulation nmTypeB = {
  .nmt = NMT_ISO14443B,
  .nbr = NBR_106,
};

// global iclass diversified key
static char Div_key[8];
static char KeyType;
static char Uid[8];

// iclass config card descriptors
char * Config_cards[]=  {
                        "AV1",
                        "AV2",
                        "AV3",
                        "KP1",
                        "KP2",
                        "KP3",
                        "CSN1",
                        "CSN2",
                        "CSN3",
                        "KRD",
                        "KRE",
                        "RSTR",
                        "RSTE",
                        NULL
                        };

char * Config_types[]=  {
                        "Audio/Visual #1 - Beep ON, LED Off, Flash GREEN on read",
                        "Audio/Visual #2 - Beep ON, LED RED, Host must flash GREEN",
                        "Audio/Visual #3 - Beep ON, LED Off, Host must flash RED and/or GREEN",
                        "Keypad Output #1 - Buffer ONE key (8 bit Dorado)",
                        "Keypad Output #2 - Buffer ONE to FIVE kets (standard 26 bit)",
                        "Keypad Output #3 - Local PIN verify",
                        "Mifare CSN #1 - 32 bit reverse output",
                        "Mifare CSN #2 - 16 bit output",
                        "Mifare CSN #3 - 34 bit output",
                        "Keyroll DISABLE - Set ELITE Key and DISABLE Keyrolling",
                        "Keyroll ENABLE - Set ELITE Key and ENABLE Keyrolling",
                        "Reset READER - Reset READER to defaults",
                        "Reset ENROLLER - Reset ENROLLER to defaults",
                        NULL
                        };

char * Config_block6[]= {
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\x87\x18",
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\xBF\x18",
                        "\x0C\x00\x00\x01\x00\x00\xBF\x18",
                        "\x0C\x00\x00\x01\x00\x00\xBF\x18",
                        "\x00\x00\x00\x00\x00\x00\x00\x1C",
                        "\x06\x00\x00\x00\x00\x00\x00\x1C",
                        NULL
                        };

char * Config_block7[]= {
                        "\xAC\x00\xA8\x8F\xA7\x80\xA9\x01",
                        "\xAC\x00\xA8\x1F\xA7\x80\xA9\x01",
                        "\xAC\x00\xA8\x0F\xA9\x03\xA7\x80",
                        "\xAE\x01\x00\x00\x00\x00\x00\x00",
                        "\xAE\x0B\xAF\xFF\xAD\x15\xB3\x03",
                        "\xAD\x6D\xB3\x03\x00\x00\x00\x00",
                        "\xAC\x01\xA7\x80\xA8\x9F\xA9\x01",
                        "\xAC\x02\xA7\x80\xA8\x9F\xA9\x01",
                        "\xAC\x03\xA7\x80\xA8\x9F\xA9\x01",
                        "\xBF\x01\xFF\xFF\xFF\xFF\xFF\xFF",
                        "\xBF\x03\xFF\xFF\xFF\xFF\xFF\xFF",
                        "\x00\x00\x00\x00\x00\x00\x00\x00",
                        "\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF",
                        NULL
                        };

char * Config_block_other= "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

// iclass card descriptors
char * Card_Types[]= 	{
			"PicoPass 16K / 16",				// 000
			"PicoPass 32K with current book 16K / 16",	// 001
			"Unknown Card Type!",				// 010
			"Unknown Card Type!",				// 011
			"PicoPass 2K",					// 100
			"Unknown Card Type!",				// 101
			"PicoPass 16K / 2",				// 110
			"PicoPass 32K with current book 16K / 2",	// 111
			};

char * Coding[]=	{
			"ISO 14443 type B only",			// 00
			"ISO 14443-2 Type B / ISO 15693",		// 01
			"RFU",						// 10
			"RFU"						// 11
			};

// add CRC to command buffer - calling routine must ensure there are two spare bytes
void iclass_add_crc(uint8_t *buffer, uint8_t length)
{
  uint16_t crc;

  crc= iclass_crc16(&buffer[1], length - 1);
  buffer[length]= (char) ((crc >> 8) & 0x00ff);
  buffer[length + 1]= (char) (crc & 0x00ff);
}

unsigned int iclass_crc16(char *data_p, unsigned char length)
{
        unsigned char i;
        unsigned int data;
        unsigned int crc = 0xffff;

        if (length == 0)
                return (~crc);

        do
                {
                for (i=0, data=(unsigned int)0xff & *data_p++; i < 8; i++, data >>= 1)
                        {
                        if ((crc & 0x0001) ^ (data & 0x0001))
                                crc = (crc >> 1) ^ 0x8408;
                        else  crc >>= 1;
                }
                }
        while (--length);

        crc = ~crc;
        data = crc;
        crc = (crc << 8) | (data >> 8 & 0xff);
        crc = crc ^ 0xBC3;
        return (crc);
}

bool
iclass_select(nfc_device *pnd, nfc_target *nt)
{
  // Let the device only try once to find a tag
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0)
    return false;

  // set up for type B
  if (nfc_initiator_select_passive_target(pnd, nmTypeB, NULL, 0, nt) < 0)
    return false;

  // Try to find an iClass
  if (nfc_initiator_select_passive_target(pnd, nmiClass, NULL, 0, nt) <= 0)
    return false;

  return true;
}

// return TRUE if auth OK or FALSE if failed
bool
iclass_authenticate(nfc_device *pnd, nfc_target nt, uint8_t *key, bool elite, bool diversify, bool debit_key)
{
  static unsigned char     update[14], data[10], nonce[16];
  static unsigned char     tmac[4], challenge[16], confirm[10];
  static uint8_t  mac[4], uid[8];
  int     i;

  // calculate diversified key
  if(diversify)
    {
    // iClass stores uid LSB first but libnfc reverses it
    for(i= 0 ; i < 8 ; ++i)
      uid[i]= nt.nti.nhi.abtUID[7 - i];
#if DEBUG
    printf("UID:");
    for(i= 0 ; i < 8 ; ++i)
      printf("%02x", (unsigned char) uid[i]);
    printf("\n");
    printf("KEY:");
    for(i= 0 ; i < 8 ; ++i)
      printf("%02x", (unsigned char) key[i]);
    printf("\n");
#endif
// need to add elite diversification code to loclass before this will work
//    if(elite)
//      divkey_elite((uint8_t *) uid, (uint8_t *) key, (uint8_t *) Div_key);
//    else
      diversifyKey((uint8_t *) uid, (uint8_t *) key, (uint8_t *) Div_key);
    }
  else
    memcpy(Div_key, key, 8);
#if DEBUG
  printf("Div KEY:");
  for(i= 0 ; i < 8 ; ++i)
    printf("%02x", (unsigned char) Div_key[i]);
  printf("\n");
#endif

  // get card challenge (block 2)
  // 88 is 'debit key'
  // 18 is 'credit key'
  if(debit_key)
    data[0]= KeyType= (unsigned char) KEYTYPE_DEBIT;
  else
    data[0]= KeyType= (unsigned char) KEYTYPE_CREDIT;
  data[1]= 0x02; // block 2
  if (nfc_initiator_transceive_bytes(pnd, (uint8_t *)&data, 2, (uint8_t *)challenge, 8, -1) < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    return false;
  }
#if DEBUG
  printf("CC: ");
  for(i= 0 ; i < 8 ; ++i)
    printf("%02X", (unsigned char) challenge[i]);
  printf("\n");
#endif

  doReaderMAC((uint8_t *) challenge, (uint8_t *) Div_key, (uint8_t *) mac);

#if DEBUG
  printf("MAC: ");
  for(i= 0 ; i < 4 ; ++i)
    printf("%02X", (unsigned char) mac[i]);
  printf("\n");
#endif

  // send NR
  // nR = 0, MAC(k1, cC · nR)
  nonce[0]= 0x05; // iclass AUTH
  memset(&nonce[1], 0x00, 4); // our challenge is all 00
  memcpy(&nonce[5], mac, 4); // plus MAC

#if DEBUG
  printf("SEND: ");
  for(i= 0 ; i < 9 ; ++i)
    printf("%02X", (unsigned char) nonce[i]);
  printf("\n");
#endif
  if (nfc_initiator_transceive_bytes(pnd, (uint8_t *)&nonce, 9, (uint8_t *)tmac, 4, -1) < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    return false;
  }

#if DEBUG
  printf("TMAC: ");
  for(i= 0 ; i < 4 ; ++i)
    printf("%02X", (unsigned char) tmac[i]);
  printf("\n");
#endif

  // TMAC should be MAC(k1, cC · nR · 0 32)
  // calculate that and compare
  memcpy(nonce, challenge, 8);
  memset(&challenge[8], 0x00, 8); // both tag and reader are all 00
  doMAC_N((uint8_t *) challenge, (uint8_t) 16, (uint8_t *) Div_key, (uint8_t *) mac);

#if DEBUG
  printf("(MAC): ");
  for(i= 0 ; i < 4 ; ++i)
    printf("%02X", (unsigned char) mac[i]);
  printf("\n");
#endif

  // auth fail?
  if(memcmp(mac, tmac, 4))
    return false;

   // send update so future writes are allowed
   update[0]= 0x87; // update
   update[1]= 0x02; // block 2
   memcpy(&update[2], challenge, 8);
   // find the non 'ff' value and subtract 1 from it
   for(i= 2 ; i < 10 ; ++i)
     if(update[i] != 0xff)
       update[i]--;
   // calculate mac
   doMAC_N((uint8_t *)&update[1], (uint8_t) 9, (uint8_t *) Div_key, (uint8_t *) mac);
   memcpy(&update[10], mac, 4);

#if DEBUG
   printf("SEND: ");
   for(i= 0 ; i < 14 ; ++i)
     printf("%02X", (unsigned char) update[i]);
   printf("\n");
#endif

  if (nfc_initiator_transceive_bytes(pnd, (uint8_t *)&update, 14, (uint8_t *)confirm, 10, -1) < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    return false;
  }

#if DEBUG
  printf("CONF: ");
  for(i= 0 ; i < 8 ; ++i)
    printf("%02X", (unsigned char) confirm[i]);
  printf("\n");
#endif

  return true;
}

bool iclass_read(nfc_device *pnd, uint8_t block, uint8_t *buff)
{
  uint8_t command[4], tmp[10], error;

  command[0]= ICLASS_READ_BLOCK;
  command[1]= block;
  iclass_add_crc(command, 2);
  if (nfc_initiator_transceive_bytes(pnd, (uint8_t *)&command, 4, tmp, 10, -1) < 0) {
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    return false;
  }
  // todo: check CRC
  memcpy(buff, tmp, 8);
  return true;
}

// at some point this went missing from loclass, so re-creating it here
void doMAC_N(uint8_t *address_data_p, uint8_t address_data_size, uint8_t *div_key_p, uint8_t mac[4])
{
        uint8_t *address_data;
        uint8_t div_key[8];
        address_data = (uint8_t*) malloc(address_data_size);
	if(address_data == NULL)
	  {
	    printf("malloc failed!\n");
	    return;
	  }

        memcpy(address_data, address_data_p, address_data_size);
        memcpy(div_key, div_key_p, 8);

        reverse_arraybytes(address_data, address_data_size);
        BitstreamIn bitstream = {address_data, address_data_size * 8, 0};
        uint8_t dest []= {0,0,0,0,0,0,0,0};
        BitstreamOut out = { dest, sizeof(dest)*8, 0 };
        MAC(div_key, bitstream, &out);
        //The output MAC must also be reversed
        reverse_arraybytes(dest, sizeof(dest));
        memcpy(mac, dest, 4);
        free(address_data);
        return;
}

// print card details and return number of blocks in application 1 (debit key protected)
uint8_t iclass_print_type(nfc_device *pnd)
{
        uint8_t type, data[8];

        if(!iclass_read(pnd, 1, data))
                return 0;

        printf("\n");

        // get 3 config bits
        type= (data[4] & 0x10) >> 2;
        type |= (data[5] & 0x80) >> 6;
        type |= (data[5] & 0x20) >> 5;
        printf("  %s\n", Card_Types[(int) type]);

        printf("  %sPersonalised\n", data[7] & 0x80 ? "Pre" : "");
        printf("  Keys %sLocked\n", data[7] & 0x08 ? "Un" : "");
        printf("  Coding: %s\n", Coding[(data[7] & 0x60) >> 5]);

        return data[0];
}

// print description of block
void iclass_print_blocktype(uint8_t block, uint8_t limit, uint8_t *data)
{
	switch(block)
	{
		case 0:
			printf("UID");
			break;
		case 1:
			printf("APP1 Blocks: %02X, ", data[0]);
                        printf("OTP1: %02X, ", data[1]);
                        printf("OTP2: %02X, ", data[2]);
                        printf("Write Lock: %02X, ", data[3]);
                        printf("Chip Config: %02X, ", data[4]);
                        printf("Memory Config: %02X, ", data[5]);
                        printf("EAS: %02X, ", data[6]);
                        printf("Fuses: %02X", data[7]);
			break;
		                case 2:
                        printf("Card Challenge");
                        break;
                case 3:
                        printf("Kd - Debit KEY (hidden)");
                        break;
                case 4:
                        printf("Kc - Credit KEY (hidden)");
                        break;
                case 5:
                        printf("Application issuer area");
                        break;
                default:
			if(block <= limit)
                        	printf("APP1 Data");
			else
				printf("APP2 Data");
                        break;
	}
}
