/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under 
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.  
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */


/*! \file s1ap_mme_decoder.c
   \brief s1ap decode procedures for MME
   \author Sebastien ROUX <sebastien.roux@eurecom.fr>
   \date 2012
   \version 0.1
*/
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>

#include "bstrlib.h"

#include "log.h"
#include "assertions.h"
#include "common_defs.h"
#include "intertask_interface.h"
#include "s1ap_common.h"
#include "s1ap_mme_handlers.h"
#include "dynamic_memory_check.h"

static int
s1ap_mme_decode_initiating (

  S1AP_S1AP_PDU_t *pdu,
  S1AP_InitiatingMessage_t *initiating_p) {
  int                                     ret = -1;
  MessageDef                             *message_p = NULL;
  asn_encode_to_new_buffer_result_t res = { NULL, {0, NULL, NULL} };
  MessagesIds message_id;

  OAILOG_FUNC_IN (LOG_S1AP);
 
  DevAssert (initiating_p != NULL);

  switch (initiating_p->procedureCode) {
    case S1AP_ProcedureCode_id_uplinkNASTransport: {
        message_id = S1AP_UPLINK_NAS_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_S1Setup: {
        message_id = S1AP_S1_SETUP_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_initialUEMessage: {
        message_id = S1AP_INITIAL_UE_MESSAGE_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_UEContextReleaseRequest: {
        message_id = S1AP_UE_CONTEXT_RELEASE_REQ_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_UECapabilityInfoIndication: {
        message_id = S1AP_UE_CAPABILITY_IND_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_NASNonDeliveryIndication: {
        message_id = S1AP_NAS_NON_DELIVERY_IND_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_ErrorIndication: {
        OAILOG_ERROR (LOG_S1AP, "Error Indication is received. Ignoring it. Procedure code = %d\n", (int)initiating_p->procedureCode);
        OAILOG_FUNC_RETURN (LOG_S1AP, ret);
      }
      break;

    case S1AP_ProcedureCode_id_Reset: {
        OAILOG_INFO (LOG_S1AP, "S1AP eNB RESET is received. Procedure code = %d\n", (int)initiating_p->procedureCode);
        message_id = S1AP_ENB_RESET_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_ENBConfigurationUpdate: {
        OAILOG_ERROR (LOG_S1AP, "eNB Configuration update is received. Ignoring it. Procedure code = %d\n", (int)initiating_p->procedureCode);
        OAILOG_FUNC_RETURN (LOG_S1AP, ret);
        /*
         * TODO- Add handling for eNB Configuration Update
         */
        // ret = s1ap_decode_s1ap_enbconfigurationupdate_ies (&message->msg.s1ap_ENBConfigurationUpdate_IEs, &initiating_p->value);
      }
      break;

      /** X2AP Handover. */
    case S1AP_ProcedureCode_id_PathSwitchRequest: {
          message_id = S1AP_PATH_SWITCH_REQUEST_LOG;
        }
        break;

      /** S1AP Handover. */
      case S1AP_ProcedureCode_id_HandoverPreparation: {
        message_id = S1AP_HANDOVER_REQUIRED_LOG;
      }
      break;
      case S1AP_ProcedureCode_id_HandoverCancel: {
        message_id = S1AP_HANDOVER_CANCEL_LOG;
      }
      break;
      case S1AP_ProcedureCode_id_eNBStatusTransfer: {
        message_id = S1AP_ENB_STATUS_TRANSFER_LOG;
      }
      break;
      case S1AP_ProcedureCode_id_HandoverNotification: {
        message_id = S1AP_HANDOVER_NOTIFY_LOG;
      }
      break;
    default: {
        OAILOG_ERROR (LOG_S1AP, "Unknown procedure ID (%d) for initiating message\n", (int)initiating_p->procedureCode);
        AssertFatal (0, "Unknown procedure ID (%d) for initiating message\n", (int)initiating_p->procedureCode);
      }
      break;
  }

  ret = 0;
  res = asn_encode_to_new_buffer(NULL, ATS_CANONICAL_XER, &asn_DEF_S1AP_S1AP_PDU, pdu);
  message_p = itti_alloc_new_message_sized (TASK_S1AP, message_id, res.result.encoded + sizeof (IttiMsgText));
  message_p->ittiMsg.s1ap_uplink_nas_log.size = res.result.encoded;
  memcpy (&message_p->ittiMsg.s1ap_uplink_nas_log.text, res.buffer, res.result.encoded);
  itti_send_msg_to_task (TASK_UNKNOWN, INSTANCE_DEFAULT, message_p);
  free_wrapper ((void**) &res.buffer);
  OAILOG_FUNC_RETURN (LOG_S1AP, ret);

}

static int
s1ap_mme_decode_successfull_outcome (

  S1AP_S1AP_PDU_t *pdu,
  S1AP_SuccessfulOutcome_t *successfullOutcome_p) {
  int                                     ret = -1;
  MessageDef                             *message_p = NULL;
  asn_encode_to_new_buffer_result_t res = { NULL, {0, NULL, NULL} };
  MessagesIds message_id;

  DevAssert (successfullOutcome_p != NULL);

  switch (successfullOutcome_p->procedureCode) {
    case S1AP_ProcedureCode_id_InitialContextSetup: {
        message_id = S1AP_INITIAL_CONTEXT_SETUP_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_UEContextRelease: {
        message_id = S1AP_UE_CONTEXT_RELEASE_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_E_RABSetup: {
        message_id = S1AP_E_RABSETUP_RESPONSE_LOG;
      }
      break;

    case S1AP_ProcedureCode_id_E_RABRelease: {
        message_id = S1AP_E_RABRELEASE_RESPONSE_LOG;
      }
      break;

    /** Handover Messaging. */
    case S1AP_ProcedureCode_id_HandoverResourceAllocation: {
      message_id = S1AP_HANDOVER_REQUEST_ACKNOWLEDGE_LOG;
    }
    break;

    default: {
        OAILOG_ERROR (LOG_S1AP, "Unknown procedure ID (%ld) for successfull outcome message\n", successfullOutcome_p->procedureCode);
        OAILOG_FUNC_RETURN (LOG_S1AP, ret);
      }
      break;
  }

  ret = 0;
  res = asn_encode_to_new_buffer(NULL, ATS_CANONICAL_XER, &asn_DEF_S1AP_S1AP_PDU, pdu);
  message_p = itti_alloc_new_message_sized (TASK_S1AP, message_id, res.result.encoded + sizeof (IttiMsgText));
  message_p->ittiMsg.s1ap_uplink_nas_log.size = res.result.encoded;
  memcpy (&message_p->ittiMsg.s1ap_uplink_nas_log.text, res.buffer, res.result.encoded);
  itti_send_msg_to_task (TASK_UNKNOWN, INSTANCE_DEFAULT, message_p);
  free_wrapper ((void**) &res.buffer);
  return ret;
}

static int
s1ap_mme_decode_unsuccessfull_outcome (
  S1AP_S1AP_PDU_t *pdu,
  S1AP_UnsuccessfulOutcome_t *unSuccessfulOutcome_p) {
  int                                     ret = -1;
  MessageDef                             *message_p = NULL;
  asn_encode_to_new_buffer_result_t res = { NULL, {0, NULL, NULL} };
  MessagesIds message_id;

  DevAssert (unSuccessfulOutcome_p != NULL);

  switch (unSuccessfulOutcome_p->procedureCode) {
    case S1AP_ProcedureCode_id_InitialContextSetup: {
        message_id = S1AP_INITIAL_CONTEXT_SETUP_LOG;
      }
      break;

      /** Handover Messaging. */
    case S1AP_ProcedureCode_id_HandoverResourceAllocation: {
      message_id = S1AP_HANDOVER_FAILED;
    }
    break;

    default: {
        OAILOG_ERROR (LOG_S1AP, "Unknown procedure ID (%d) for unsuccessfull outcome message\n", (int)unSuccessfulOutcome_p->procedureCode);
        OAILOG_FUNC_RETURN (LOG_S1AP, ret);
      }
      break;
  }

  ret = 0;
  res = asn_encode_to_new_buffer(NULL, ATS_CANONICAL_XER, &asn_DEF_S1AP_S1AP_PDU, pdu);
  message_p = itti_alloc_new_message_sized (TASK_S1AP, message_id, res.result.encoded + sizeof (IttiMsgText));
  message_p->ittiMsg.s1ap_uplink_nas_log.size = res.result.encoded;
  memcpy (&message_p->ittiMsg.s1ap_uplink_nas_log.text, res.buffer, res.result.encoded);
  itti_send_msg_to_task (TASK_UNKNOWN, INSTANCE_DEFAULT, message_p);
  free_wrapper ((void**) &res.buffer);
  return ret;
}

int
s1ap_mme_decode_pdu (
  S1AP_S1AP_PDU_t *pdu,
  const_bstring const raw,
  int offset) {
  asn_dec_rval_t                          dec_ret = {(RC_OK)};
  DevAssert (raw != NULL);

  dec_ret = aper_decode (NULL, &asn_DEF_S1AP_S1AP_PDU, (void **)&pdu, bdataofs(raw, offset), blength(raw) - offset, 0, 0);

  if (dec_ret.code != RC_OK) {
    OAILOG_ERROR (LOG_S1AP, "Failed to decode PDU\n");
    return -1;
  }

  switch (pdu->present) {
    case S1AP_S1AP_PDU_PR_initiatingMessage:
      s1ap_mme_decode_initiating (pdu, &pdu->choice.initiatingMessage);
      break;

    case S1AP_S1AP_PDU_PR_successfulOutcome:
      s1ap_mme_decode_successfull_outcome (pdu, &pdu->choice.successfulOutcome);
      break;

    case S1AP_S1AP_PDU_PR_unsuccessfulOutcome:
      s1ap_mme_decode_unsuccessfull_outcome (pdu, &pdu->choice.unsuccessfulOutcome);
      break;

    default:
      OAILOG_ERROR (LOG_S1AP, "Unknown message outcome (%d) or not implemented", (int)pdu->present);
      return -1;
  }

  return (dec_ret.consumed + 7) / 8;
}
