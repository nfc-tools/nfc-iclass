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
 * @file nfc-iclass.c
 * @brief HID iClass (picopass) tool
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <getopt.h>
#include <stdbool.h>

#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>
#include <fcntl.h>

#include "nfc-utils.h"
#include "iclass.h"
#include "nfc-iclass.h"

#include <openssl/des.h>

// loclass includes
#include "elite_crack.h"

static nfc_device *pnd;
static nfc_target nt;
// unpermuted version of https://github.com/ss23/hid-iclass-key/blob/master/key
// permuted is 3F90EBF0910F7B6F
uint8_t *Default_kd= (uint8_t *) "\xAF\xA7\x85\xA7\xDA\xB3\x33\x78"; 

// HID DES keys needed for this to work!
static DES_cblock Key1 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static DES_cblock Key2 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static DES_key_schedule SchKey1,SchKey2;

#define MAXWRITE 2000 // 0xff * 8 byte blocks - 5 * 8 byte reserved blocks
int main(int argc, char **argv)
{
  int i, j, c, app1_limit, app2_limit;
  int infile, outfile, writelen= 0;
  static uint8_t buff[8], buff2[8], kc[8], kd[8], kr[8], krekey[8], *key, writedata[MAXWRITE];
  static uint8_t ku[8], kp[8];
  bool got_kc= false, got_kd= false, got_kr= false, dump= false, config= false, elite= false;
  bool rekey= false, got_kp= false, got_ku= false;
  unsigned int tmp, writeblock= 0;
  uint8_t *configdata[2]; // config card block data
  uint8_t *configtype; // the config card type requested
  char *p;

  while ((c= getopt(argc, argv, "c:C:d:ehk:no:p:r:R:u:w:")) != -1)
  {
    switch (c)
      {
      case 'c':
        if(strlen(optarg) != 16)
          return errorexit("\nCredit KEY must be 16 HEX digits!\n");
        for(i= 0 ; i < 8 ; ++i)
          {
          if(sscanf(&optarg[i * 2], "%02x", &tmp) != 1)
            return errorexit("\nInvalid HEX in key!\n");
	  kc[i]= (uint8_t) tmp;
          }
	got_kc= true;
        continue;

      case 'C':
        configtype= optarg;
        if(*configtype == '?')
	  {
          iclass_print_configs();
	  return 0;
	  }
        else
          {
          for(i= 0 ; ; ++i)
            {
            if(Config_cards[i] == NULL)
              break;
            if(!strncasecmp(configtype, Config_cards[i], strlen(Config_cards[i])))
              {
              config= true;
              configdata[0]= Config_block6[i];
              configdata[1]= Config_block7[i];
              break;
              }
            }
          if(!config)
            {
            printf("\nInvalid CONFIG card!\n");
            return 1;
            }
          }
        continue;

      case 'd':
        if(strlen(optarg) != 16)
          return errorexit("\nDebit KEY must be 16 HEX digits!\n");
        for(i= 0 ; i < 8 ; ++i)
          {
          if(sscanf(&optarg[i * 2], "%02x", &tmp) != 1)
            return errorexit("\nInvalid HEX in key!\n");
	  kd[i]= (uint8_t) tmp;
          }
	got_kd= true;
        continue;

      case 'e':
	elite= true;
	continue;

      case 'k':
        if(strlen(optarg) != 16)
          return errorexit("\nKeyroll KEY must be 16 HEX digits!\n");
        for(i= 0 ; i < 8 ; ++i)
          {
          if(sscanf(&optarg[i * 2], "%02x", &tmp) != 1)
            return errorexit("\nInvalid HEX in key!\n");
	  kr[i]= (uint8_t) tmp;
          }
	got_kr= true;
	// this config card will not work unless you have the HID master 3DES key!
	if(!memcmp(Key1, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) || !memcmp(Key2, "\x00\x00\x00\x00\x00\x00\x00\x00", 8))
          return errorexit("Master 3DES KEY required for KEYROLLing! (see source comments)\n");
        continue;

      case 'p':
        if(strlen(optarg) != 16)
          return errorexit("\nPermute KEY must be 16 HEX digits!\n");
        for(i= 0 ; i < 8 ; ++i)
          {
          if(sscanf(&optarg[i * 2], "%02x", &tmp) != 1)
            return errorexit("\nInvalid HEX in key!\n");
	  kp[i]= (uint8_t) tmp;
          }
	got_kp= true;
        continue;

      case 'r':
        if(strlen(optarg) != 16)
          return errorexit("\nRe-key KEY must be 16 HEX digits!\n");
        for(i= 0 ; i < 8 ; ++i)
          {
          if(sscanf(&optarg[i * 2], "%02x", &tmp) != 1)
            return errorexit("\nInvalid HEX in key!\n");
	  krekey[i]= (uint8_t) tmp;
          }
	rekey= true;
        continue;

      case 'R':
        if(strlen(optarg) != 16)
          return errorexit("\nRe-key KEY must be 16 HEX digits!\n");
        for(i= 0 ; i < 8 ; ++i)
          {
          if(sscanf(&optarg[i * 2], "%02x", &tmp) != 1)
            return errorexit("\nInvalid HEX in key!\n");
	  krekey[i]= (uint8_t) tmp;
          }
	rekey= true;
	Elite_Override= true;
        continue;

      case 'u':
        if(strlen(optarg) != 16)
          return errorexit("\nUnpermute KEY must be 16 HEX digits!\n");
        for(i= 0 ; i < 8 ; ++i)
          {
          if(sscanf(&optarg[i * 2], "%02x", &tmp) != 1)
            return errorexit("\nInvalid HEX in key!\n");
	  ku[i]= (uint8_t) tmp;
          }
	got_ku= true;
        continue;

        case 'w':
          // don't allow writing of reserved blocks!
         if(sscanf(optarg, "%x", &tmp) != 1 || tmp < 5)
           return errorexit("Can't write - Bad block number! (Lowest valid block is 5)\n");
         writeblock= (int) tmp;
         continue;

      case 'o':
        if((outfile= open(optarg, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) <= 0)
          return errorexit("Can't open output file!\n");
	dump= true;
	continue;

      case 'h':
      default:
        printf("\nUsage: %s [options] [BINARY FILE|HEX DATA]\n", argv[0]);
        printf("\n  Options:\n\n");
        printf("\t-c <KEY>      Use CREDIT KEY Kc / APP2 (default is DEBIT KEY Kd / APP1)\n");
        printf("\t-C <?|CARD>   Create CONFIG card (? prints list of config cards)\n");
        printf("\t-d <KEY>      Use non-default DEBIT KEY for APP1\n");
        printf("\t-e            AUTH KEY is ELITE\n");
        printf("\t-h            You're looking at it\n");
        printf("\t-k <KEY>      Keyroll KEY for CONFIG card\n");
        printf("\t-n            Do not DIVERSIFY key\n");
        printf("\t-o <FILE>     Write TAG data to FILE\n");
        printf("\t-p <KEY>      Permute KEY\n");
        printf("\t-r <KEY>      Re-Key with KEY (assumes new key is ELITE)\n");
        printf("\t-R <KEY>      Re-Key to non-ELITE\n");
        printf("\t-u <KEY>      Unpermute KEY\n");
        printf("\t-w <BLOCK>    WRITE to tag starting from BLOCK (specify # in HEX)\n");
        printf("\n");
        printf("\tIf no KEY is specified, default HID Kd (APP1) will be used\n");
        printf("\n");
        printf("  Examples:\n\n");
	printf("    Use non-default key for APP1:\n\n");
	printf("\t%s -d DEADBEEFCAFEF00D\n\n", argv[0]);
	printf("    Dump contents of APP2:\n\n");
	printf("\t%s -c 0DC442031337D00F\n\n", argv[0]);
	printf("    Write APP1 blocks 8 & 9:\n\n");
	printf("\t%s -w 8 aabbccddaabbccddaabbccddaabbccdd\n\n", argv[0]);
	printf("      or\n\n");
	printf("\t%s -w 8 /tmp/iclass-8-9-dump.icd\n\n", argv[0]);
        return 1;
      }
  }

  // do non-tag related stuff first
  if(got_kp)
    {
    printf("\n  Permuting key: %02x%02x%02x%02x%02x%02x%02x%02x\n", kp[0], kp[1], kp[2], kp[3], kp[4], kp[5], kp[6], kp[7]);
    permutekey(kp, buff);
    printf("  Permuted key:  %02x%02x%02x%02x%02x%02x%02x%02x\n", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6], buff[7]);
    }

  if(got_ku)
    {
    printf("\n  Unpermuting key: %02x%02x%02x%02x%02x%02x%02x%02x\n", ku[0], ku[1], ku[2], ku[3], ku[4], ku[5], ku[6], ku[7]);
    permutekey_rev(ku, buff);
    printf("  Unpermuted key:  %02x%02x%02x%02x%02x%02x%02x%02x\n", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6], buff[7]);
    }

  // check for conflicting args
  if(writeblock && config)
    printf("*** WARNING! WRITE may overwrite CONFIG blocks! ***");

  // prepare data for writing
  if(writeblock)
    {
    if(optind >= argc)
      return errorexit("Can't write - No data!\n");
    p= argv[argc - 1];
    // is it a file?
    if((infile= open(p, O_RDONLY)) > 0)
      {
      if((writelen= read(infile, writedata, MAXWRITE)) <= 0)
        return errorexit("\nRead failed!\n");
      }
    else
      {
      writelen= strlen(p) / 2;
      for(i= 0 ; i < writelen && i < MAXWRITE ; ++i, p += 2)
        {
        if(sscanf(p, "%02x", &tmp) != 1)
          return errorexit("\nInvalid HEX in data!\n");
        writedata[i]= (char) tmp;
        }
      close(infile);
      }
    if(writelen > MAXWRITE)
      return errorexit("Can't write - Data too long!\n");
    if(writelen % 8)
      return errorexit("Can't write - Data must be 8 byte blocks!\n");
    }

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC device
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("Error opening NFC device");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("\nNFC device: %s opened\n", nfc_device_get_name(pnd));

  // Try to find an iClass
  if (!iclass_select(pnd, &nt)) {
    ERR("no tag was found\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Get the info from the current tag
  printf("Found iClass card with UID: ");
  size_t  szPos;
  for (szPos = 0; szPos < 8; szPos++) {
    printf("%02x", nt.nti.nhi.abtUID[szPos]);
  }
  printf("\n");

  if(!(app1_limit= (int) iclass_print_type(pnd, &app2_limit)))
    {
    printf("  could not determine card type!\n");
    app1_limit= 0xff;
    }

  printf("\n  reading header blocks...\n\n");
  for(i= 0 ; i < 6 ; ++i)
    {
    printf("    Block 0x%02x: ", i);
    if(!iclass_read(pnd, i, buff))
      {
      for(j= 0 ; j < 8 ; ++j)
        printf("%02x", (uint8_t) buff[j]);
      printf("  ");
      for(j= 0 ; j < 8 ; ++j)
	printf("%c", isprint(buff[j]) ? (char) buff[j] : '.');    
      printf("  ");
      iclass_print_blocktype(i, app1_limit, buff);
      if(dump)
        if(write(outfile, buff, 8) != 8)
          errorexit("Write to output file failed!\n");
      }
    else
      printf("read failed!");
    printf("\n");
    }
  printf("\n");

  // authenticate with default Debit key if no key provided
  if(got_kd)
    key= kd;
  else
    key= Default_kd;
  printf("  authing to APP1\n\n");
  if(!iclass_authenticate(pnd, nt, key, elite, true, true))
  {
    ERR("authentication failed\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // write config card if specified
  if(config)
    {
    // keyroll card
    if(!strncasecmp(configtype, "KR", 2))
      {
      if(!got_kr)
        {
        printf("\nPlease specify KEYROLL key!\n");
        return 1;
        }
      if(app1_limit < 0x16)
        return errorexit("\nAPP1 too small for KEYROLL!\n");
      printf("\n  Writing KEYROLL card: %s\n\n", configtype);
        for(i= 0 ; i < 2 ; ++i)
          {
          if(iclass_write(pnd, i +6, configdata[i]))
            return errorexit("Write failed!\n");
          else
            printf("    Written block %02x\n", i + 6);
          }
        for(i= 0x08 ; i < 0x0d ; ++i)
          if(iclass_write(pnd, i, Config_block_other))
            return errorexit("Write failed!\n");
          else
            printf("    Written block %02x\n", i);
        // update keyroll blocks
        // keyroll cards are 3DES encrypted for block 0x0d upwards
        DES_set_key_unchecked(&Key1, &SchKey1);
        DES_set_key_unchecked(&Key2, &SchKey2);
        DES_ecb2_encrypt((unsigned char (*)[8]) kr, (unsigned char (*)[8]) buff, &SchKey1, &SchKey2, DES_ENCRYPT);
        if(iclass_write(pnd, 0x0d, buff))
          return errorexit("Write failed!\n");
        else
          printf("    Written block 0d (KEYROLL KEY)\n");
        DES_ecb2_encrypt((unsigned char (*)[8]) Config_block_other, (unsigned char (*)[8]) buff, &SchKey1, &SchKey2, DES_ENCRYPT);
        for(i= 0x0e ; i < 0x14 ; ++i)
          if(iclass_write(pnd, i, buff))
            return errorexit("Write failed!\n");
          else
            printf("    Written block %02x\n", i);
        buff2[0]= 0x15;
        memcpy(&buff2[1], kr, 7);
        DES_ecb2_encrypt((unsigned char (*)[8]) buff2, (unsigned char (*)[8]) buff, &SchKey1, &SchKey2, DES_ENCRYPT);
        if(iclass_write(pnd, 0x14, buff))
          return errorexit("Write failed!\n");
        else
          printf("    Written block 14 (Partial KEYROLL KEY)\n");
        memset(buff2, 0xff, 8);
        buff2[0]= kr[7];
        DES_ecb2_encrypt((unsigned char (*)[8]) buff2, (unsigned char (*)[8]) buff, &SchKey1, &SchKey2, DES_ENCRYPT);
        if(iclass_write(pnd, 0x15, buff))
          return errorexit("Write failed!\n");
        else
          printf("    Written block 15 (Partial KEYROLL KEY)\n");
        DES_ecb2_encrypt((unsigned char (*)[8]) Config_block_other, (unsigned char (*)[8]) buff, &SchKey1, &SchKey2, DES_ENCRYPT);
        for(i= 0x16 ; i <= app1_limit ; ++i)
          if(iclass_write(pnd, i, buff))
            return errorexit("Write failed!\n");
          else
            printf("    Written block %02x\n", i);
        }
    else
      {
      //standard config card
      printf("\n  Writing CONFIG card: %s\n\n", configtype);
      for(i= 0 ; i < 2 ; ++i)
        if(iclass_write(pnd, i + 6, configdata[i]))
          return errorexit("Write failed!\n");
        else
          printf("    Written block %02x\n", i + 6);
        for(i= 0x08 ; i <= app1_limit ; ++i)
          if(iclass_write(pnd, i, Config_block_other))
            return errorexit("Write failed!\n");
          else
            printf("    Written block %02x\n", i);
      }
    printf("\n");
    }

  // write to APP1
  if(writeblock && writeblock <= app1_limit)
    {
    printf("\n  writing...\n\n");
    for(i= 0 ; i < writelen ; i += 8, writeblock++)
      {
      if(iclass_write(pnd, writeblock, &writedata[i]))
         return errorexit("Write failed!\n");
      else
         {
         printf("    Block 0x%02x: ", writeblock);
         for(j= 0 ; j < 8 ; ++j)
           printf("%02x", (uint8_t) writedata[j]);
         printf("  ");
         for(j= 0 ; j < 8 ; ++j)
           printf("%c", isprint(writedata[j]) ? (char) writedata[j] : '.');
         printf("  ");
         iclass_print_blocktype(writeblock, app1_limit, writedata);
	 }
      printf("\n");
      }
    printf("\n");
    }

  // show APP1
  printf("  reading APP1 blocks...\n\n");
  for(i= 6 ; i <= app1_limit ; ++i)
  {
    printf("    Block 0x%02x: ", i);
    if(!iclass_read(pnd, i, buff))
    {
      for(j= 0 ; j < 8 ; ++j)
        printf("%02x", (uint8_t) buff[j]);
      printf("  ");
      for(j= 0 ; j < 8 ; ++j)
	printf("%c", isprint(buff[j]) ? (char) buff[j] : '.');    
      printf("  ");
      iclass_print_blocktype(i, app1_limit, buff);
      if(dump)
        if(write(outfile, buff, 8) != 8)
          return errorexit("Write to output file failed!\n");
    }
    else
      printf("read failed!");
    printf("\n");
  }
  printf("\n");

  // show APP2 if requested
  if(got_kc)
  {
    printf("  authing to APP2\n\n");
    key= kc;
    if(!iclass_authenticate(pnd, nt, key, elite, true, false)) {
      ERR("authentication failed\n");
      nfc_close(pnd);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }

    // write to APP2
    if(writeblock && writeblock > app1_limit)
      {
      printf("\n  writing...\n\n");
      for(i= 0 ; i < writelen ; i += 8, writeblock++)
        {
        if(iclass_write(pnd, writeblock, &writedata[i]))
           return errorexit("Write failed!\n");
        else
           {
           printf("    Block 0x%02x: ", writeblock);
           for(j= 0 ; j < 8 ; ++j)
             printf("%02x", (uint8_t) writedata[j]);
           printf("  ");
           for(j= 0 ; j < 8 ; ++j)
             printf("%c", isprint(writedata[j]) ? (char) writedata[j] : '.');
           printf("  ");
           iclass_print_blocktype(writeblock, app1_limit, writedata);
           }
        printf("\n");
        }
      printf("\n");
      }

    printf("  reading APP2 blocks:\n\n");
    for(i= app1_limit + 1 ; i <= app2_limit ; ++i)
    {
      printf("    Block 0x%02x: ", i);
      if(!iclass_read(pnd, i, buff))
      {
        for(j= 0 ; j < 8 ; ++j)
          printf("%02x", (uint8_t) buff[j]);
        printf("  ");
        for(j= 0 ; j < 8 ; ++j)
  	printf("%c", isprint(buff[j]) ? (char) buff[j] : '.');    
        printf("  ");
        iclass_print_blocktype(i, app1_limit, buff);
        if(dump)
          if(write(outfile, buff, 8) != 8)
            return errorexit("Write to output file failed!\n");
      }
      else
        printf("read failed!");
      printf("\n");
    }
  printf("\n");
  }


  if(dump)
    close(outfile);

   // rekey last so we don't have to worry about re-authing
  if(rekey)
    {
    // block 3 (debit key) or 4 (credit key) writes will be xor'd as appropriate
    if(got_kc)
      {
      if(iclass_write(pnd, 4, krekey))
      return errorexit("Re-Key CREDIT failed!\n");
      }
    else
      {
      if(iclass_write(pnd, 3, krekey))
        return errorexit("Re-Key DEBIT failed!\n");
      }
      printf("\n  Re-Key OK\n");
    }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}

char errorexit(char *message)
{
    printf("%s\n", message);
    return 1;
}

bool strncasecmp(char *s1, char *s2, int len)
{
  char *us1 = s1, *us2 = s2;

  while (tolower(*us1++) == tolower(*us2++) && --len)
    ;
  return (tolower(*--us1) != tolower(*--us2));
}
