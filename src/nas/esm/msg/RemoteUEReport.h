/*
 * RemoteUEReport.h
 *
 *  Created on: May 16, 2019
 *      Author: nepes
 */

#ifndef SRC_NAS_ESM_MSG_REMOTEUEREPORT_H_
#define SRC_NAS_ESM_MSG_REMOTEUEREPORT_H_

#include "MessageType.h"
#include "3gpp_24.007.h"
#include "RemoteUEContext.h"
#include "PKMFAddress.h" 

/* Minimum length macro. Formed by minimum length of each mandatory field */
#define REMOTE_UE_REPORT_MINIMUM_LENGTH (3)

/* Maximum length macro. Formed by maximum length of each field */
#define REMOTE_UE_REPORT_MAXIMUM_LENGTH (16300)

typedef struct remote_ue_report_msg_tag {
  /* Mandatory fields */
  eps_protocol_discriminator_t                           protocoldiscriminator:4;
  ebi_t                                                  epsbeareridentity:4;
  pti_t                                                  proceduretransactionidentity;
  message_type_t                                         messagetype;
  /* Optional fields */
  pkmf_address_t                   						           pkmfaddress;
} remote_ue_report_msg;

int decode_remote_ue_report(remote_ue_report_msg *remoteuereport, uint8_t *buffer, uint32_t len);
int encode_remote_ue_report(remote_ue_report_msg *remoteuereport, uint8_t *buffer, uint32_t len);
#endif /* SRC_NAS_ESM_MSG_REMOTEUEREPORT_H_ */
