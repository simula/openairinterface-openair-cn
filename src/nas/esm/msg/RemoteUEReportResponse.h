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

#include "ProtocolDiscriminator.h"
#include "EpsBearerIdentity.h"
#include "ProcedureTransactionIdentity.h"

#ifndef OPENAIR3_NAS_COMMON_ESM_MSG_REMOTEUEREPORT_H_
#define OPENAIR3_NAS_COMMON_ESM_MSG_REMOTEUEREPORT_H_



typedef struct remote_ue_report_response_msg_tag {
  /* Mandatory fields */
  ProtocolDiscriminator               protocoldiscriminator:4;
  EpsBearerIdentity                   epsbeareridentity:4;
  ProcedureTransactionIdentity        proceduretransactionidentity;
  /* Optional fields */
  //PKMFAddress                    		pkmfaddress;
  //RemoteUEContext        				remoteuecontext;
} remote_ue_report_response_msg;

int decode_remote_ue_report_response(remote_ue_report_response_msg *remoteuereportresponse, uint8_t *buffer, uint32_t len);

int encode_remote_ue_report_response(remote_ue_report_response_msg *remoteuereportresponse, uint8_t *buffer, uint32_t len);

#endif /* SRC_NAS_ESM_MSG_REMOTEUEREPORTRESPONSE_H_ */
