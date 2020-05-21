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

static nfc_device *pnd;
static nfc_target nt;
// unpermuted version of https://github.com/ss23/hid-iclass-key/blob/master/key
// permuted is 3F90EBF0910F7B6F
uint8_t *Default_kd= (uint8_t *) "\xAF\xA7\x85\xA7\xDA\xB3\x33\x78"; 

#define MAXWRITE 2000 // 0xff * 8 byte blocks - 5 * 8 byte reserved blocks
int main(int argc, char **argv)
{
  int i, j, c, app1_limit, app2_limit;
  int infile, outfile= 0, writelen= 0;
  static uint8_t buff[8], kc[8], kd[8], *key, writedata[MAXWRITE];
  bool got_kc= false, got_kd= false;
  unsigned int tmp, writeblock= 0;
  char *configdata[2]; // config card block data
  char *configtype; // the config card type requested
  char *p;

  while ((c= getopt(argc, argv, "c:C:d:ehno:r:Rw:")) != -1)
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
/*          for(i= 0 ; ; ++i)
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
*/          }
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

        case 'w':
          // don't allow writing of reserved blocks!
         if(sscanf(optarg, "%x", &tmp) != 1 || tmp < 5)
           return errorexit("Can't write - Bad block number! (Lowest valid block is 5)\n");
         writeblock= (int) tmp;
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
        printf("\t-n            Do not DIVERSIFY key\n");
        printf("\t-o <FILE>     Write TAG data to FILE\n");
        printf("\t-r <KEY>      Re-Key with KEY (assumes new key is ELITE)\n");
        printf("\t-R            Re-Key to non-ELITE\n");
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
        return 1;
      }
  }

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

  printf("NFC device: %s opened\n", nfc_device_get_name(pnd));

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
    if(iclass_read(pnd, i, buff))
      {
      for(j= 0 ; j < 8 ; ++j)
        printf("%02x", (uint8_t) buff[j]);
      printf("  ");
      for(j= 0 ; j < 8 ; ++j)
	printf("%c", isprint(buff[j]) ? (char) buff[j] : '.');    
      printf("  ");
      iclass_print_blocktype(i, app1_limit, buff);
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
  if(!iclass_authenticate(pnd, nt, key, false, true, true))
  {
    ERR("authentication failed\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if(writeblock)
    {
    printf("\n  writing...\n\n");
    for(i= 0 ; i < writelen ; i += 8, writeblock++)
      {
      if(!iclass_write(pnd, writeblock, &writedata[i]))
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
    if(iclass_read(pnd, i, buff))
    {
      for(j= 0 ; j < 8 ; ++j)
        printf("%02x", (uint8_t) buff[j]);
      printf("  ");
      for(j= 0 ; j < 8 ; ++j)
	printf("%c", isprint(buff[j]) ? (char) buff[j] : '.');    
      printf("  ");
      iclass_print_blocktype(i, app1_limit, buff);
    }
    else
      printf("read failed!");
    printf("\n");
  }
  printf("\n");

  // show APP2 if requested
  if(got_kc)
  {
    printf("  reading APP2 blocks:\n\n");
    key= kc;
    if(!iclass_authenticate(pnd, nt, key, false, true, false)) {
      ERR("authentication failed\n");
      nfc_close(pnd);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
    for(i= app1_limit + 1 ; i <= app2_limit ; ++i)
    {
      printf("    Block 0x%02x: ", i);
      if(iclass_read(pnd, i, buff))
      {
        for(j= 0 ; j < 8 ; ++j)
          printf("%02x", (uint8_t) buff[j]);
        printf("  ");
        for(j= 0 ; j < 8 ; ++j)
  	printf("%c", isprint(buff[j]) ? (char) buff[j] : '.');    
        printf("  ");
        iclass_print_blocktype(i, app1_limit, buff);
      }
      else
        printf("read failed!");
      printf("\n");
    }
  printf("\n");
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

