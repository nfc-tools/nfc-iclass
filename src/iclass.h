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
 * @file iclass.h
 * @brief provide samples structs and functions to manipulate HID iClass (picopass) tags using libnfc
 */

#ifndef _ICLASS_H_
#  define _ICLASS_H_

#include <nfc/nfc-types.h>
#include "cipherutils.h"

#define ICLASS_ACTIVATE_ALL		0x0A
#define ICLASS_SELECT			0x0C
#define ICLASS_READ_BLOCK		0x0C
#define ICLASS_ANTICOL			0x81

#define KEYTYPE_DEBIT   0x88
#define KEYTYPE_CREDIT  0x18


//bool nfc_initiator_iclass_cmd(nfc_device *pnd, const iclass_req req, iclass_res *pres);
bool iclass_select(nfc_device *pnd, nfc_target *nt);
bool iclass_authenticate(nfc_device *pnd, nfc_target nt, uint8_t *key, bool elite, bool diversify, bool debit_key);
unsigned int iclass_crc16(char *data_p, unsigned char length);
void doMAC_N(uint8_t *address_data_p, uint8_t address_data_size, uint8_t *div_key_p, uint8_t mac[4]);
bool iclass_read(nfc_device *pnd, uint8_t block, uint8_t *buff);
void iclass_add_crc(uint8_t *buffer, uint8_t length);
#endif // _ICLASS_H_
