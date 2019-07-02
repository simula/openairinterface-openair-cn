/*
 * PKMFAddress.h
 *
 *  Created on: Jun 6, 2019
 *      Author: nepes
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef SRC_NAS_IES_PKMFADDRESS_H_
#define SRC_NAS_IES_PKMFADDRESS_H_

typedef struct pkmf_address_s {
  uint8_t  spare:5;
#define ADDRESS_TYPE  001
  uint8_t  addresstype:3;
#define PKMF_IPV4 ADDRESS
  uint32_t  pkmfipv4address ;
}pkmf_address_t;

int encode_pkmf_address(pkmf_address_t *pkmfaddress, uint8_t iei, uint8_t *buffer, uint32_t len);

int decode_pkmf_address(pkmf_address_t *pkmfaddress, uint8_t iei, uint8_t *buffer, uint32_t len);


#endif /* SRC_NAS_IES_PKMFADDRESS_H_ */
