/*
 * RemoteUEReportResponse.h
 *
 *  Created on: Jun 11, 2019
 *      Author: nepes
 */

#ifndef SRC_NAS_ESM_MSG_REMOTEUEREPORTRESPONSE_H_
#define SRC_NAS_ESM_MSG_REMOTEUEREPORTRESPONSE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "3gpp_24.007.h"

typedef struct remote_ue_report_response_msg_tag {
  /* Mandatory fields */
	eps_protocol_discriminator_t               protocoldiscriminator:4;
	ebi_t                   				   epsbeareridentity:4;
	pti_t	                                   proceduretransactionidentity;
  /* Optional fields */
  //PKMFAddress                    		pkmfaddress;
  //RemoteUEContext        				remoteuecontext;
} remote_ue_report_response_msg;

int decode_remote_ue_report_response(remote_ue_report_response_msg *remoteuereportresponse, uint8_t *buffer, uint32_t len);

int encode_remote_ue_report_response(remote_ue_report_response_msg *remoteuereportresponse, uint8_t *buffer, uint32_t len);

#endif /* SRC_NAS_ESM_MSG_REMOTEUEREPORTRESPONSE_H_ */
