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

/*! \file s1ap_mme_nas_procedures.c
  \brief
  \author Sebastien ROUX, Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "bstrlib.h"

#include "S1AP_GBR-QosInformation.h"

#include "dynamic_memory_check.h"
#include "assertions.h"
#include "hashtable.h"
#include "log.h"
#include "msc.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "asn1_conversions.h"
#include "s1ap_common.h"
#include "s1ap_mme_encoder.h"
#include "s1ap_mme_itti_messaging.h"
#include "s1ap_mme_nas_procedures.h"
#include "s1ap_mme.h"
#include "mme_config.h"

/* Every time a new UE is associated, increment this variable.
   But care if it wraps to increment also the mme_ue_s1ap_id_has_wrapped
   variable. Limit: UINT32_MAX (in stdint.h).
*/
//static mme_ue_s1ap_id_t                 mme_ue_s1ap_id = 0;
//static bool                             mme_ue_s1ap_id_has_wrapped = false;

extern const char                      *s1ap_direction2String[];
extern hash_table_ts_t g_s1ap_mme_id2assoc_id_coll; // contains sctp association id, key is mme_ue_s1ap_id;

//static bool
//s1ap_add_bearer_context_to_setup_list (S1AP_E_RABToBeSetupListHOReqIEs_t * const e_RABToBeSetupListHOReq_p,
//    S1AP_E_RABToBeSetupItemHOReq_t        * e_RABToBeSetupHO_p, bearer_contexts_to_be_created_t * bc_tbc);

//static bool
//s1ap_add_bearer_context_to_switch_list (S1AP_E_RABToBeSwitchedULListIEs_t * const e_RABToBeSwitchedListHOReq_p,
//    S1AP_E_RABToBeSwitchedULItem_t        * e_RABToBeSwitchedHO_p, bearer_context_t * bearer_ctxt_p);

//------------------------------------------------------------------------------
int
s1ap_mme_handle_initial_ue_message (
  const sctp_assoc_id_t assoc_id,
  const sctp_stream_id_t stream,
  S1AP_S1AP_PDU_t *pdu)
{
  S1AP_InitialUEMessage_t                *container;
  S1AP_InitialUEMessage_IEs_t            *ie = NULL, *ie_e_tmsi, *ie_csg_id, *ie_gummei, *ie_cause;

  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *eNB_ref = NULL;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;

  OAILOG_FUNC_IN (LOG_S1AP);
  container = &pdu->choice.initiatingMessage.value.choice.InitialUEMessage;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID, true);

  OAILOG_INFO (LOG_S1AP, "Received S1AP INITIAL_UE_MESSAGE eNB_UE_S1AP_ID " ENB_UE_S1AP_ID_FMT "\n", (enb_ue_s1ap_id_t)ie->value.choice.ENB_UE_S1AP_ID);

  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME, MSC_S1AP_ENB, NULL, 0, "0 initialUEMessage/%s assoc_id %u stream %u " ENB_UE_S1AP_ID_FMT " ",
          s1ap_direction2String[pdu->present - 1], assoc_id, stream, (enb_ue_s1ap_id_t)ie->value.choice.ENB_UE_S1AP_ID);

  if ((eNB_ref = s1ap_is_enb_assoc_id_in_list (assoc_id)) == NULL) {
    OAILOG_WARNING (LOG_S1AP, "Unknown eNB on assoc_id %d\n", assoc_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  // eNB UE S1AP ID is limited to 24 bits
  enb_ue_s1ap_id = (enb_ue_s1ap_id_t) (ie->value.choice.ENB_UE_S1AP_ID & 0x00ffffff);
  OAILOG_INFO (LOG_S1AP, "New Initial UE message received with eNB UE S1AP ID: " ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
  ue_ref = s1ap_is_ue_enb_id_in_list (eNB_ref, enb_ue_s1ap_id);

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container, S1AP_ProtocolIE_ID_id_GUMMEIType, false);
  if (ie) {
    OAILOG_WARNING (LOG_S1AP, "Received (unhandled) GUMMEI-Type %ld\n", ie->value.choice.GUMMEIType);
  }

  if (ue_ref == NULL) {
    tai_t                                   tai = {0};
    gummei_t                                gummei = {.plmn = {0}, .mme_code = 0, .mme_gid = 0}; // initialized after
    s_tmsi_t                                s_tmsi = {.mme_code = 0, .m_tmsi = INVALID_M_TMSI};
    ecgi_t                                  ecgi = {.plmn = {0}, .cell_identity = {0}};
    csg_id_t                                csg_id = 0;

    /*
     * This UE eNB Id has currently no known s1 association.
     * * * * Create new UE context by associating new mme_ue_s1ap_id.
     * * * * Update eNB UE list.
     * * * * Forward message to NAS.
     */
    if ((ue_ref = s1ap_new_ue (assoc_id, enb_ue_s1ap_id)) == NULL) {
      // If we failed to allocate a new UE return -1
      OAILOG_ERROR (LOG_S1AP, "S1AP:Initial UE Message- Failed to allocate S1AP UE Context, eNBUeS1APId:" ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    ue_ref->s1_ue_state = S1AP_UE_WAITING_CSR;

    ue_ref->enb_ue_s1ap_id = enb_ue_s1ap_id;
    // Will be allocated by NAS
    ue_ref->mme_ue_s1ap_id = INVALID_MME_UE_S1AP_ID;

    ue_ref->s1ap_ue_context_rel_timer.id  = S1AP_TIMER_INACTIVE_ID;
    ue_ref->s1ap_ue_context_rel_timer.sec = S1AP_UE_CONTEXT_REL_COMP_TIMER;

    ue_ref->s1ap_handover_completion_timer.id  = S1AP_TIMER_INACTIVE_ID;
    ue_ref->s1ap_handover_completion_timer.sec = S1AP_HANDOVER_COMPLETION_TIMER;

    // On which stream we received the message
    ue_ref->sctp_stream_recv = stream;
    ue_ref->sctp_stream_send = ue_ref->enb->next_sctp_stream;

    /*
     * Increment the sctp stream for the eNB association.
     * If the next sctp stream is >= instream negociated between eNB and MME, wrap to first stream.
     * TODO: search for the first available stream instead.
     */
    ue_ref->enb->next_sctp_stream += 1;
    if (ue_ref->enb->next_sctp_stream >= ue_ref->enb->instreams) {
      ue_ref->enb->next_sctp_stream = 1;
    }

    /** MME_UE_S1AP_ID will be set in MME_APP layer. */

    s1ap_dump_enb (ue_ref->enb);
    // TAI mandatory IE
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container, S1AP_ProtocolIE_ID_id_TAI, true);
    OCTET_STRING_TO_TAC (&ie->value.choice.TAI.tAC, tai.tac);
    DevAssert (ie->value.choice.TAI.pLMNidentity.size == 3);
    TBCD_TO_PLMN_T(&ie->value.choice.TAI.pLMNidentity, &tai.plmn);

    // CGI mandatory IE
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container, S1AP_ProtocolIE_ID_id_EUTRAN_CGI, true);
    DevAssert (ie->value.choice.EUTRAN_CGI.pLMNidentity.size == 3);
    TBCD_TO_PLMN_T(&ie->value.choice.EUTRAN_CGI.pLMNidentity, &ecgi.plmn);
    BIT_STRING_TO_CELL_IDENTITY (&ie->value.choice.EUTRAN_CGI.cell_ID, ecgi.cell_identity);

    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_e_tmsi, container, S1AP_ProtocolIE_ID_id_S_TMSI, false);
    if (ie_e_tmsi) {
      OCTET_STRING_TO_MME_CODE(&ie_e_tmsi->value.choice.S_TMSI.mMEC, s_tmsi.mme_code);
      OCTET_STRING_TO_M_TMSI(&ie_e_tmsi->value.choice.S_TMSI.m_TMSI, s_tmsi.m_tmsi);
    }

    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_csg_id, container,
                               S1AP_ProtocolIE_ID_id_CSG_Id, false);
    if (ie_csg_id) {
      csg_id = BIT_STRING_to_uint32(&ie_csg_id->value.choice.CSG_Id);
    }

    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_gummei, container,
                               S1AP_ProtocolIE_ID_id_GUMMEI_ID, false);
    memset(&gummei, 0, sizeof(gummei));

    if (ie_gummei) {
      //TODO OCTET_STRING_TO_PLMN(&initialUEMessage_p->gummei_id.pLMN_Identity, gummei.plmn);
      OCTET_STRING_TO_MME_GID(&ie_gummei->value.choice.GUMMEI.mME_Group_ID, gummei.mme_gid);
      OCTET_STRING_TO_MME_CODE(&ie_gummei->value.choice.GUMMEI.mME_Code, gummei.mme_code);
    }
    /*
     * We received the first NAS transport message: initial UE message.
     * * * * Send a NAS ESTAeNBBLISH IND to NAS layer
     */
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container,
                               S1AP_ProtocolIE_ID_id_NAS_PDU, true);
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_cause, container,
                               S1AP_ProtocolIE_ID_id_RRC_Establishment_Cause, true);

    s1ap_mme_itti_s1ap_initial_ue_message (assoc_id,
        ue_ref->enb->enb_id,
        ue_ref->enb_ue_s1ap_id,
        ue_ref->mme_ue_s1ap_id,
        ie->value.choice.NAS_PDU.buf,
        ie->value.choice.NAS_PDU.size,
        &tai,
        &ecgi,
        ie_cause->value.choice.RRC_Establishment_Cause,
        ie_e_tmsi ? &s_tmsi:NULL,
        ie_csg_id ? &csg_id:NULL,
        ie_gummei ? &gummei:NULL,
        NULL, // CELL ACCESS MODE
        NULL, // GW Transport Layer Address
        NULL  //Relay Node Indicator
        );
  }else {
    OAILOG_ERROR (LOG_S1AP, "S1AP:Initial UE Message- Duplicate ENB_UE_S1AP_ID. Ignoring the message, eNBUeS1APId:" ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
  }


  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}


//------------------------------------------------------------------------------
int
s1ap_mme_handle_uplink_nas_transport (
  const sctp_assoc_id_t assoc_id,
  __attribute__((unused)) const sctp_stream_id_t stream,
  S1AP_S1AP_PDU_t *pdu)
{
  OAILOG_FUNC_IN (LOG_S1AP);
  S1AP_UplinkNASTransport_t              *container;
  S1AP_UplinkNASTransport_IEs_t          *ie = NULL, *ie_nas_pdu = NULL;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *enb_ref = NULL;
  tai_t                                   tai = {0};
  ecgi_t                                  ecgi = {.plmn = {0}, .cell_identity = {0}};
  mme_ue_s1ap_id_t                        mme_ue_s1ap_id = 0;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;

  container = &pdu->choice.initiatingMessage.value.choice.UplinkNASTransport;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID, true);
  enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID, true);
  mme_ue_s1ap_id = ie->value.choice.MME_UE_S1AP_ID;

  if (INVALID_MME_UE_S1AP_ID == ie->value.choice.MME_UE_S1AP_ID) {
    OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT message MME_UE_S1AP_ID unknown\n");

    enb_ref = s1ap_is_enb_assoc_id_in_list (assoc_id);

    if (!(ue_ref = s1ap_is_ue_enb_id_in_list ( enb_ref, enb_ue_s1ap_id))) {
      OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT No UE is attached to this enb_ue_s1ap_id: " ENB_UE_S1AP_ID_FMT "\n",enb_ue_s1ap_id);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  } else {
    OAILOG_INFO (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT message MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT "\n",
        mme_ue_s1ap_id);

    if (!(ue_ref = s1ap_is_ue_mme_id_in_list (mme_ue_s1ap_id))) {
      OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT No UE is attached to this mme_ue_s1ap_id: " MME_UE_S1AP_ID_FMT "\n", mme_ue_s1ap_id);
      /** Check via the received ENB_UE_S1AP_ID and the ENB_ID. */
      enb_ref = s1ap_is_enb_assoc_id_in_list (assoc_id);
      if (!(ue_ref = s1ap_is_ue_enb_id_in_list ( enb_ref, enb_ue_s1ap_id))) {
        OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT No UE is attached to this enb_ue_s1ap_id (after searching with mmeUeS1apId): " ENB_UE_S1AP_ID_FMT "\n",enb_ue_s1ap_id);
        OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
      }else{
        OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT and found the UE reference via enb_ue_s1ap_id: " ENB_UE_S1AP_ID_FMT \
            " (after searching with mmeUeS1apId) and enbId %d. \n",enb_ue_s1ap_id, enb_ref->enb_id);
      }
    }
  }

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie_nas_pdu, container, S1AP_ProtocolIE_ID_id_NAS_PDU, true);


//  if (S1AP_UE_CONNECTED != ue_ref->s1_ue_state) {
//    OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT while UE in state != S1AP_UE_CONNECTED\n");
//    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_S1AP_MME,
//                        MSC_S1AP_ENB,
//                        NULL, 0,
//                        "0 uplinkNASTransport/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas len %u",
//                        s1ap_direction2String[message->direction],
//                        (mme_ue_s1ap_id_t)uplinkNASTransport_p->mme_ue_s1ap_id,
//                        (enb_ue_s1ap_id_t)uplinkNASTransport_p->eNB_UE_S1AP_ID,
//                        uplinkNASTransport_p->nas_pdu.size);
//
//    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
//  }

  // TAI mandatory IE
  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_TAI, true);
  OCTET_STRING_TO_TAC (&ie->value.choice.TAI.tAC, tai.tac);
  DevAssert (ie->value.choice.TAI.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&ie->value.choice.TAI.pLMNidentity, &tai.plmn);

  // CGI mandatory IE
  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_EUTRAN_CGI, true);
  DevAssert (ie->value.choice.EUTRAN_CGI.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&ie->value.choice.EUTRAN_CGI.pLMNidentity, &ecgi.plmn);
  BIT_STRING_TO_CELL_IDENTITY (&ie->value.choice.EUTRAN_CGI.cell_ID, ecgi.cell_identity);

  // TODO optional GW Transport Layer Address


  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 uplinkNASTransport/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas len %u",
                      s1ap_direction2String[pdu->present - 1],
                      mme_ue_s1ap_id,
                      enb_ue_s1ap_id,
                      ie_nas_pdu->value.choice.NAS_PDU.size);

  bstring b = blk2bstr(ie_nas_pdu->value.choice.NAS_PDU.buf, ie_nas_pdu->value.choice.NAS_PDU.size);
  s1ap_mme_itti_nas_uplink_ind (mme_ue_s1ap_id,
                                &b,
                                &tai,
                                &ecgi);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}


//------------------------------------------------------------------------------
int
s1ap_mme_handle_nas_non_delivery (
    __attribute__((unused)) sctp_assoc_id_t assoc_id,
  sctp_stream_id_t stream,
  S1AP_S1AP_PDU_t *pdu)
{

  S1AP_NASNonDeliveryIndication_t        *container;
  S1AP_NASNonDeliveryIndication_IEs_t    *ie = NULL, *ie_nas_pdu;
  ue_description_t                       *ue_ref = NULL;
  mme_ue_s1ap_id_t                        mme_ue_s1ap_id = 0;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;


  OAILOG_FUNC_IN (LOG_S1AP);

  container = &pdu->choice.initiatingMessage.value.choice.NASNonDeliveryIndication;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID, true);
  mme_ue_s1ap_id = ie->value.choice.MME_UE_S1AP_ID;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID, true);
  enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie_nas_pdu, container,
                             S1AP_ProtocolIE_ID_id_NAS_PDU, true);

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_Cause, true);

  /*
   * UE associated signalling on stream == 0 is not valid.
   */
  if (stream == 0) {
    OAILOG_NOTICE (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION message on invalid sctp stream 0\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  OAILOG_NOTICE (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION message MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT "\n",      mme_ue_s1ap_id, enb_ue_s1ap_id);

  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 NASNonDeliveryIndication/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " cause %u nas len %u",
                      s1ap_direction2String[pdu->present - 1],
                      mme_ue_s1ap_id,
                      enb_ue_s1ap_id,
                      ie->value.choice.Cause,
                      ie_nas_pdu->value.choice.NAS_PDU.size);

  if ((ue_ref = s1ap_is_ue_mme_id_in_list (mme_ue_s1ap_id))
      == NULL) {
    OAILOG_DEBUG (LOG_S1AP, "No UE is attached to this mme UE s1ap id: " MME_UE_S1AP_ID_FMT "\n", mme_ue_s1ap_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  if (ue_ref->s1_ue_state != S1AP_UE_CONNECTED) {
    OAILOG_DEBUG (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION while UE in state != S1AP_UE_CONNECTED\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  //TODO: forward NAS PDU to NAS
  s1ap_mme_itti_nas_non_delivery_ind (mme_ue_s1ap_id,
                                      ie_nas_pdu->value.choice.NAS_PDU.buf,
                                      ie_nas_pdu->value.choice.NAS_PDU.size,
                                      &ie->value.choice.Cause);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
int
s1ap_generate_downlink_nas_transport (
  const enb_ue_s1ap_id_t enb_ue_s1ap_id,
  const mme_ue_s1ap_id_t ue_id,
  const uint32_t         enb_id,
  STOLEN_REF bstring *payload)
{
  OAILOG_FUNC_IN (LOG_S1AP);
  ue_description_t                       *ue_ref = NULL;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  void                                   *id = NULL;

  // Try to retrieve SCTP association id using mme_ue_s1ap_id
  if (HASH_TABLE_OK ==  hashtable_ts_get (&g_s1ap_mme_id2assoc_id_coll, (const hash_key_t)ue_id, (void **)&id)) {
    sctp_assoc_id_t sctp_assoc_id = (sctp_assoc_id_t)(uintptr_t)id;
    enb_description_t  *enb_ref = s1ap_is_enb_assoc_id_in_list (sctp_assoc_id);
    if (enb_ref) {
      OAILOG_ERROR (LOG_S1AP, "SEARCHING UE REFERENCE for SCTP association id %d,  enbUeS1apId " ENB_UE_S1AP_ID_FMT " and enbId %d. \n", sctp_assoc_id, enb_ue_s1ap_id, enb_ref->enb_id);
      ue_ref = s1ap_is_ue_enb_id_in_list (enb_ref,enb_ue_s1ap_id);
    } else {
      OAILOG_ERROR (LOG_S1AP, "No eNB for SCTP association id %d \n", sctp_assoc_id);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  }

  // TODO remove soon:
  if (!ue_ref) {
    ue_ref = s1ap_is_ue_mme_id_in_list (ue_id);
  }
  // finally!
  if (!ue_ref) {
    /*
     * If the UE-associated logical S1-connection is not established,
     * * * * the MME shall allocate a unique MME UE S1AP ID to be used for the UE.
     */
    OAILOG_WARNING(LOG_S1AP, "Unknown UE MME ID " MME_UE_S1AP_ID_FMT ", This case is not handled right now\n", ue_id);
    ue_ref = s1ap_is_enb_ue_s1ap_id_in_list_per_enb(enb_ue_s1ap_id, enb_id);
      if(!ue_ref){
        OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
      }
  }

  /*
   * We have fount the UE in the list.
   * * * * Create new IE list message and encode it.
   */
  S1AP_S1AP_PDU_t                        pdu = {0};
  S1AP_DownlinkNASTransport_t            *out;
  S1AP_DownlinkNASTransport_IEs_t        *ie = NULL;

  memset(&pdu, 0, sizeof(pdu));
  pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
  pdu.choice.initiatingMessage.procedureCode = S1AP_ProcedureCode_id_downlinkNASTransport;
  pdu.choice.initiatingMessage.criticality = S1AP_Criticality_ignore;
  pdu.choice.initiatingMessage.value.present = S1AP_InitiatingMessage__value_PR_DownlinkNASTransport;
  out = &pdu.choice.initiatingMessage.value.choice.DownlinkNASTransport;

  ue_ref->s1_ue_state = S1AP_UE_CONNECTED;
  /*
   * Setting UE informations with the ones found in ue_ref
   */
  /* mandatory */
  ie = (S1AP_DownlinkNASTransport_IEs_t *)calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID;
  ie->value.choice.ENB_UE_S1AP_ID = ue_ref->mme_ue_s1ap_id;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
  /* mandatory */
  ie = (S1AP_DownlinkNASTransport_IEs_t *)calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID;
  ie->value.choice.ENB_UE_S1AP_ID = ue_ref->enb_ue_s1ap_id;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
  /* mandatory */
  ie = (S1AP_DownlinkNASTransport_IEs_t *)calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_NAS_PDU;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_NAS_PDU;
  /*eNB
   * Fill in the NAS pdu
   */
  OCTET_STRING_fromBuf (&ie->value.choice.NAS_PDU, (char *)bdata(*payload), blength(*payload));
  bdestroy(*payload);
  *payload = NULL;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  if (s1ap_mme_encode_pdu (&pdu, &buffer_p, &length) < 0) {
    // TODO: handle something
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }


  OAILOG_NOTICE (LOG_S1AP, "Send S1AP DOWNLINK_NAS_TRANSPORT message ue_id = " MME_UE_S1AP_ID_FMT " MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
      ue_id, ue_ref->mme_ue_s1ap_id, enb_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
      MSC_S1AP_ENB,
      NULL, 0,
      "0 downlinkNASTransport/initiatingMessage ue_id " MME_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id" ENB_UE_S1AP_ID_FMT " nas length %u",
      ue_id, ue_ref->mme_ue_s1ap_id, enb_ue_s1ap_id, length);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b , ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);

  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
int s1ap_generate_s1ap_e_rab_setup_req (itti_s1ap_e_rab_setup_req_t * const e_rab_setup_req)
{
  OAILOG_FUNC_IN (LOG_S1AP);
  ue_description_t                       *ue_ref = NULL;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  void                                   *id = NULL;
  const enb_ue_s1ap_id_t                  enb_ue_s1ap_id = e_rab_setup_req->enb_ue_s1ap_id;
  const mme_ue_s1ap_id_t                  ue_id       = e_rab_setup_req->mme_ue_s1ap_id;

  hashtable_ts_get (&g_s1ap_mme_id2assoc_id_coll, (const hash_key_t)ue_id, (void **)&id);
  if (id) {
    sctp_assoc_id_t sctp_assoc_id = (sctp_assoc_id_t)(uintptr_t)id;
    enb_description_t  *enb_ref = s1ap_is_enb_assoc_id_in_list (sctp_assoc_id);
    if (enb_ref) {
      ue_ref = s1ap_is_ue_enb_id_in_list (enb_ref,enb_ue_s1ap_id);
    }
  }
  // TODO remove soon:
  if (!ue_ref) {
    ue_ref = s1ap_is_ue_mme_id_in_list (ue_id);
  }
  // finally!
  if (!ue_ref) {
    /*
     * If the UE-associated logical S1-connection is not established,
     * * * * the MME shall allocate a unique MME UE S1AP ID to be used for the UE.
     */
    OAILOG_DEBUG (LOG_S1AP, "Unknown UE MME ID " MME_UE_S1AP_ID_FMT ", This case is not handled right now\n", ue_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  } else {
    /*
     * We have found the UE in the list.
     * Create new IE list message and encode it.
     */
    S1AP_S1AP_PDU_t                        pdu = {0};
    S1AP_E_RABSetupRequest_t              *out = NULL;
    S1AP_E_RABSetupRequestIEs_t           *ie = NULL;
    S1AP_E_RABSetupRequestIEs_t           *ie_list = NULL;

    memset(&pdu, 0, sizeof(pdu));
    pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage.procedureCode = S1AP_ProcedureCode_id_E_RABSetup;
    pdu.choice.initiatingMessage.criticality = S1AP_Criticality_ignore;
    pdu.choice.initiatingMessage.value.present = S1AP_InitiatingMessage__value_PR_E_RABSetupRequest;
    out = &pdu.choice.initiatingMessage.value.choice.E_RABSetupRequest;

    ue_ref->s1_ue_state = S1AP_UE_CONNECTED;


    /*
     * Setting UE informations with the ones found in ue_ref
     */

    /* mandatory */
    ie = (S1AP_E_RABSetupRequestIEs_t *)calloc(1, sizeof(S1AP_E_RABSetupRequestIEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_E_RABSetupRequestIEs__value_PR_MME_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = ue_ref->mme_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
    /* mandatory */
    ie = (S1AP_E_RABSetupRequestIEs_t *)calloc(1, sizeof(S1AP_E_RABSetupRequestIEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_E_RABSetupRequestIEs__value_PR_ENB_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = ue_ref->enb_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
    /* mandatory */
    ie_list = (S1AP_E_RABSetupRequestIEs_t *)calloc(1, sizeof(S1AP_E_RABSetupRequestIEs_t));
    ie_list->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupListBearerSUReq;
    ie_list->criticality = S1AP_Criticality_reject;
    ie_list->value.present = S1AP_E_RABSetupRequestIEs__value_PR_E_RABToBeSetupListBearerSUReq;

    for  (int i= 0; i < e_rab_setup_req->e_rab_to_be_setup_list.no_of_items; i++) {
      S1AP_E_RABToBeSetupItemBearerSUReqIEs_t *ie_item = (S1AP_E_RABToBeSetupItemBearerSUReqIEs_t *)calloc(1, sizeof(S1AP_E_RABToBeSetupItemBearerSUReqIEs_t));
      ie_item->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupItemBearerSUReq;
      ie_item->criticality = S1AP_Criticality_reject;
      ie_item->value.present = S1AP_E_RABToBeSetupItemBearerSUReqIEs__value_PR_E_RABToBeSetupItemBearerSUReq;

      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RAB_ID = e_rab_setup_req->e_rab_to_be_setup_list.item[i].e_rab_id;
      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.qCI = e_rab_setup_req->e_rab_to_be_setup_list.item[i].e_rab_level_qos_parameters.qci;

      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel =
          e_rab_setup_req->e_rab_to_be_setup_list.item[i].e_rab_level_qos_parameters.allocation_and_retention_priority.priority_level;

      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionCapability =
          e_rab_setup_req->e_rab_to_be_setup_list.item[i].e_rab_level_qos_parameters.allocation_and_retention_priority.pre_emption_capability;

      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionVulnerability =
          e_rab_setup_req->e_rab_to_be_setup_list.item[i].e_rab_level_qos_parameters.allocation_and_retention_priority.pre_emption_vulnerability;
      /* OPTIONAL */
      gbr_qos_information_t *gbr_qos_information = &e_rab_setup_req->e_rab_to_be_setup_list.item[i].e_rab_level_qos_parameters.gbr_qos_information;
      if ((gbr_qos_information->e_rab_maximum_bit_rate_downlink)    ||
          (gbr_qos_information->e_rab_maximum_bit_rate_uplink)      ||
          (gbr_qos_information->e_rab_guaranteed_bit_rate_downlink) ||
          (gbr_qos_information->e_rab_guaranteed_bit_rate_uplink)) {

        OAILOG_NOTICE (LOG_S1AP, "Encoding of e_RABlevelQoSParameters.gbrQosInformation\n");

        ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.gbrQosInformation = calloc(1, sizeof(S1AP_GBR_QosInformation_t));
        //ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.gbrQosInformation = &gbrQosInformation[i];
        //memset(&gbrQosInformation[i], 0, sizeof(gbrQosInformation[i]));
        if (ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.gbrQosInformation) {
          asn_uint642INTEGER(&ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.gbrQosInformation->e_RAB_MaximumBitrateDL,
              gbr_qos_information->e_rab_maximum_bit_rate_downlink);

          asn_uint642INTEGER(&ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.gbrQosInformation->e_RAB_MaximumBitrateUL,
              gbr_qos_information->e_rab_maximum_bit_rate_uplink);

          asn_uint642INTEGER(&ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.gbrQosInformation->e_RAB_GuaranteedBitrateDL,
              gbr_qos_information->e_rab_guaranteed_bit_rate_downlink);

          asn_uint642INTEGER(&ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.e_RABlevelQoSParameters.gbrQosInformation->e_RAB_GuaranteedBitrateUL,
              gbr_qos_information->e_rab_guaranteed_bit_rate_uplink);
        }
      } else {
        OAILOG_NOTICE (LOG_S1AP, "NOT Encoding of e_RABlevelQoSParameters.gbrQosInformation\n");
      }

      INT32_TO_OCTET_STRING (e_rab_setup_req->e_rab_to_be_setup_list.item[i].gtp_teid, &ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.gTP_TEID);

      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.transportLayerAddress.buf = calloc (blength(e_rab_setup_req->e_rab_to_be_setup_list.item[i].transport_layer_address), sizeof (uint8_t));
      memcpy (ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.transportLayerAddress.buf,
          e_rab_setup_req->e_rab_to_be_setup_list.item[i].transport_layer_address->data,
          blength(e_rab_setup_req->e_rab_to_be_setup_list.item[i].transport_layer_address));

      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.transportLayerAddress.size = blength(e_rab_setup_req->e_rab_to_be_setup_list.item[i].transport_layer_address);
      ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.transportLayerAddress.bits_unused = 0;

      OCTET_STRING_fromBuf (&ie_item->value.choice.E_RABToBeSetupItemBearerSUReq.nAS_PDU, (char *)bdata(e_rab_setup_req->e_rab_to_be_setup_list.item[i].nas_pdu),
          blength(e_rab_setup_req->e_rab_to_be_setup_list.item[i].nas_pdu));

      ASN_SEQUENCE_ADD (&ie_list, ie_item);
    }
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie_list);

    if (s1ap_mme_encode_pdu (&pdu, &buffer_p, &length) < 0) {
      // TODO: handle something
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    OAILOG_NOTICE (LOG_S1AP, "Send S1AP DOWNLINK_NAS_TRANSPORT message ue_id = " MME_UE_S1AP_ID_FMT " MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
                ue_id, (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id);
    MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                        MSC_S1AP_ENB,
                        NULL, 0,
                        "0 downlinkNASTransport/initiatingMessage ue_id " MME_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id" ENB_UE_S1AP_ID_FMT " nas length %u",
                        ue_id, (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id, length);
    bstring b = blk2bstr(buffer_p, length);
    s1ap_mme_itti_send_sctp_request (&b , ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  }

  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);

}

//------------------------------------------------------------------------------
int s1ap_generate_s1ap_e_rab_release_req (itti_s1ap_e_rab_release_req_t * const e_rab_release_req)
{
  OAILOG_FUNC_IN (LOG_S1AP);
  uint32_t                                length = 0;
  const enb_ue_s1ap_id_t                  enb_ue_s1ap_id = e_rab_release_req->enb_ue_s1ap_id;
  const mme_ue_s1ap_id_t                  ue_id       = e_rab_release_req->mme_ue_s1ap_id;
  ue_description_t                       *ue_ref = NULL;
  uint8_t                                *buffer_p = NULL;
  void                                   *id = NULL;

  hashtable_ts_get (&g_s1ap_mme_id2assoc_id_coll, (const hash_key_t)ue_id, (void **)&id);
  if (id) {
    sctp_assoc_id_t sctp_assoc_id = (sctp_assoc_id_t)(uintptr_t)id;
    enb_description_t  *enb_ref = s1ap_is_enb_assoc_id_in_list (sctp_assoc_id);
    if (enb_ref) {
      ue_ref = s1ap_is_ue_enb_id_in_list (enb_ref,enb_ue_s1ap_id);
    }
  }
  // TODO remove soon:
  if (!ue_ref) {
    ue_ref = s1ap_is_ue_mme_id_in_list (ue_id);
  }
  // finally!
  if (!ue_ref) {
    /*
     * If the UE-associated logical S1-connection is not established,
     * * * * the MME shall allocate a unique MME UE S1AP ID to be used for the UE.
     */
    OAILOG_DEBUG (LOG_S1AP, "Unknown UE MME ID " MME_UE_S1AP_ID_FMT ", This case is not handled right now\n", ue_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  } else {
    /*
     * We have found the UE in the list.
     * Create new IE list message and encode it.
     */
    S1AP_S1AP_PDU_t                        pdu = {0};
    S1AP_E_RABReleaseCommand_t            *out = NULL;
    S1AP_E_RABReleaseCommandIEs_t         *ie = NULL;

    memset(&pdu, 0, sizeof(pdu));
    pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage.procedureCode = S1AP_ProcedureCode_id_E_RABRelease;
    pdu.choice.initiatingMessage.criticality = S1AP_Criticality_ignore;
    pdu.choice.initiatingMessage.value.present = S1AP_InitiatingMessage__value_PR_E_RABReleaseCommand;
    out = &pdu.choice.initiatingMessage.value.choice.E_RABReleaseCommand;

    /* mandatory */
    ie = (S1AP_E_RABReleaseCommandIEs_t *)calloc(1, sizeof(S1AP_E_RABReleaseCommandIEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_E_RABReleaseCommandIEs__value_PR_MME_UE_S1AP_ID;
    ie->value.choice.MME_UE_S1AP_ID = ue_ref->mme_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
    /* mandatory */
    ie = (S1AP_E_RABReleaseCommandIEs_t *)calloc(1, sizeof(S1AP_E_RABReleaseCommandIEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_E_RABReleaseCommandIEs__value_PR_ENB_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = e_rab_release_req->enb_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);


    ue_ref->s1_ue_state = S1AP_UE_CONNECTED;

    if (e_rab_release_req->e_rab_to_be_release_list.no_of_items) {
      ie = (S1AP_E_RABReleaseCommandIEs_t *)calloc(1, sizeof(S1AP_E_RABReleaseCommandIEs_t));
      ie->id = S1AP_ProtocolIE_ID_id_E_RABToBeReleasedList;
      ie->criticality = S1AP_Criticality_reject;
      ie->value.present = S1AP_E_RABReleaseCommandIEs__value_PR_E_RABList;
      //ie->value.choice.E_RABList.list

      for  (int i= 0; i < e_rab_release_req->e_rab_to_be_release_list.no_of_items; i++) {
        S1AP_E_RABItem_t *erab = (S1AP_E_RABItem_t *)calloc(1, sizeof(S1AP_E_RABItem_t));
        erab->e_RAB_ID = e_rab_release_req->e_rab_to_be_release_list.item[i].e_rab_id;
        erab->cause.present = S1AP_Cause_PR_nas;
        erab->cause.choice.nas = 0;
        ASN_SEQUENCE_ADD (&ie->value.choice.E_RABList.list, erab);
      }
    }
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

    /** Set the NAS message outside of the EBI list. */
    if(e_rab_release_req->nas_pdu) {
      ie = (S1AP_E_RABReleaseCommandIEs_t *)calloc(1, sizeof(S1AP_E_RABReleaseCommandIEs_t));
      ie->id = S1AP_ProtocolIE_ID_id_NAS_PDU;
      ie->criticality = S1AP_Criticality_reject;
      ie->value.present = S1AP_E_RABReleaseCommandIEs__value_PR_NAS_PDU;
      OCTET_STRING_fromBuf (&ie->value.choice.NAS_PDU, (char *)bdata(e_rab_release_req->nas_pdu),
          blength(e_rab_release_req->nas_pdu));
      ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
    } else {
      OAILOG_INFO(LOG_S1AP, "No NAS message received for S1AP E-RAB release command for ueId " MME_UE_S1AP_ID_FMT" .\n", e_rab_release_req->mme_ue_s1ap_id);
    }

    if (s1ap_mme_encode_pdu (&pdu, &buffer_p, &length) < 0) {
      // TODO: handle something
      OAILOG_ERROR (LOG_S1AP, "Encoding of s1ap_E_RABReleaseCommandIEs failed \n");
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    OAILOG_NOTICE (LOG_S1AP, "Send S1AP E_RABRelease command MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
        ue_ref->mme_ue_s1ap_id, e_rab_release_req->enb_ue_s1ap_id);
    MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                        MSC_S1AP_ENB,
                        NULL, 0,
                        "0 E_RABSetup/initiatingMessage mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id" ENB_UE_S1AP_ID_FMT " nas length %u",
                        ue_ref->mme_ue_s1ap_id, e_rab_release_req->enb_ue_s1ap_id, length);
    bstring b = blk2bstr(buffer_p, length);
    s1ap_mme_itti_send_sctp_request (&b , ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  }

  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);

}

//------------------------------------------------------------------------------
void
s1ap_handle_conn_est_cnf (
  const itti_mme_app_connection_establishment_cnf_t * const conn_est_cnf_pP)
{
  /*
   * We received create session response from S-GW on S11 interface abstraction.
   * At least one bearer has been established. We can now send s1ap initial context setup request
   * message to eNB.
   */
  //uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  S1AP_S1AP_PDU_t                         pdu = {0};
  S1AP_InitialContextSetupRequest_t      *out;
  S1AP_InitialContextSetupRequestIEs_t   *ie = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (conn_est_cnf_pP != NULL);

  ue_ref = s1ap_is_ue_mme_id_in_list (conn_est_cnf_pP->ue_id);
  if (!ue_ref) {
    OAILOG_ERROR (LOG_S1AP, "Not creating a new ue reference for mme ue s1ap id (" MME_UE_S1AP_ID_FMT ").\n",conn_est_cnf_pP->ue_id);
    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /*
   * Start the outcome response timer.
   * * * * When time is reached, MME consider that procedure outcome has failed.
   */
  //     timer_setup(mme_config.s1ap_config.outcome_drop_timer_sec, 0, TASK_S1AP, INSTANCE_DEFAULT,
  //                 TIMER_ONE_SHOT,
  //                 NULL,
  //                 &ue_ref->outcome_response_timer_id);
  /*
   * Insert the timer in the MAP of mme_ue_s1ap_id <-> timer_id
   */
  //     s1ap_timer_insert(ue_ref->mme_ue_s1ap_id, ue_ref->outcome_response_timer_id);
  // todo: remove them after testing
  OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ CONNECTION ESTABLISHMENT %" PRIXPTR " \n", (uintptr_t)((void*)ue_ref));
  OAILOG_DEBUG(LOG_S1AP, "SET ENB_UE_S1AP_ID  @ CONNECTION ESTABLISHMENT %d \n", ue_ref->enb_ue_s1ap_id);

  memset(&pdu, 0, sizeof(pdu));
  pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
  pdu.choice.initiatingMessage.procedureCode = S1AP_ProcedureCode_id_InitialContextSetup;
  pdu.choice.initiatingMessage.criticality = S1AP_Criticality_ignore;
  pdu.choice.initiatingMessage.value.present = S1AP_InitiatingMessage__value_PR_InitialContextSetupRequest;
  out = &pdu.choice.initiatingMessage.value.choice.InitialContextSetupRequest;

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_MME_UE_S1AP_ID;
  ie->value.choice.ENB_UE_S1AP_ID = ue_ref->mme_ue_s1ap_id;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_ENB_UE_S1AP_ID;
  ie->value.choice.ENB_UE_S1AP_ID = ue_ref->enb_ue_s1ap_id;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /*
   * uEaggregateMaximumBitrateDL and uEaggregateMaximumBitrateUL expressed in term of bits/sec
   */
  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_uEaggregateMaximumBitrate;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UEAggregateMaximumBitrate;
  asn_uint642INTEGER (&ie->value.choice.UEAggregateMaximumBitrate.uEaggregateMaximumBitRateDL, conn_est_cnf_pP->ue_ambr.br_dl);
  asn_uint642INTEGER (&ie->value.choice.UEAggregateMaximumBitrate.uEaggregateMaximumBitRateUL, conn_est_cnf_pP->ue_ambr.br_ul);
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_E_RABToBeSetupListCtxtSUReq;

  for (int item = 0; item < conn_est_cnf_pP->no_of_e_rabs; item++) {
    S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t  *e_rab_tobesetup_item = (S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t *)calloc(1, sizeof(S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t));
    S1AP_E_RABToBeSetupItemCtxtSUReq_t *e_RABToBeSetup;

    e_rab_tobesetup_item->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq;
    e_rab_tobesetup_item->criticality = S1AP_Criticality_reject;
    e_rab_tobesetup_item->value.present = S1AP_E_RABToBeSetupItemCtxtSUReqIEs__value_PR_E_RABToBeSetupItemCtxtSUReq;
    e_RABToBeSetup = &e_rab_tobesetup_item->value.choice.E_RABToBeSetupItemCtxtSUReq;

    e_RABToBeSetup->e_RAB_ID = conn_est_cnf_pP->e_rab_id[item];;     //5;
    e_RABToBeSetup->e_RABlevelQoSParameters.qCI = conn_est_cnf_pP->e_rab_level_qos_qci[item];

    if (conn_est_cnf_pP->nas_pdu[item]) {
      // NAS PDU is optional in rab_setup
      e_RABToBeSetup->nAS_PDU = (S1AP_NAS_PDU_t *)calloc(1, sizeof(S1AP_NAS_PDU_t));
      e_RABToBeSetup->nAS_PDU->size = blength(conn_est_cnf_pP->nas_pdu[item]); // todo: slen?
      e_RABToBeSetup->nAS_PDU->buf  = conn_est_cnf_pP->nas_pdu[item]->data;
    }

    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel = conn_est_cnf_pP->e_rab_level_qos_priority_level[item];
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionCapability = conn_est_cnf_pP->e_rab_level_qos_preemption_capability[item];
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionVulnerability = conn_est_cnf_pP->e_rab_level_qos_preemption_vulnerability[item];
    /*
     * Set the GTP-TEID. This is the S1-U S-GW TEID
     */
    INT32_TO_OCTET_STRING (conn_est_cnf_pP->gtp_teid[item], &e_RABToBeSetup->gTP_TEID);
    // S-GW IP address(es) for user-plane
    e_RABToBeSetup->transportLayerAddress.buf = calloc (blength(conn_est_cnf_pP->transport_layer_address[item]), sizeof (uint8_t));
    memcpy (e_RABToBeSetup->transportLayerAddress.buf, conn_est_cnf_pP->transport_layer_address[item]->data, blength(conn_est_cnf_pP->transport_layer_address[item]));
    e_RABToBeSetup->transportLayerAddress.size = blength(conn_est_cnf_pP->transport_layer_address[item]);
    e_RABToBeSetup->transportLayerAddress.bits_unused = 0;
    // todo: IPv6 address of SAE-GW
//    /*
//     * S-GW IP address(es) for user-plane
//     */    if (conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv6) {
//      if (offset == 0) {
//        /*
//         * Both IPv4 and IPv6 provided
//         */
//        /*
//         * TODO: check memory allocation
//         */
//        e_RABToBeSetup->transportLayerAddress.buf = calloc (16, sizeof (uint8_t));
//      } else {
//        /*
//         * Only IPv6 supported
//         */
//        /*
//         * TODO: check memory allocation
//         */
//        e_RABToBeSetup->transportLayerAddress.buf = realloc (e_RABToBeSetup->transportLayerAddress.buf, (16 + offset) * sizeof (uint8_t));
//      }
//
//      memcpy (&e_RABToBeSetup->transportLayerAddress.buf[offset], conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv6_address, 16);
//      e_RABToBeSetup->transportLayerAddress.size = 16 + offset;
//      e_RABToBeSetup->transportLayerAddress.bits_unused = 0;
//    }

    ASN_SEQUENCE_ADD(&ie->value.choice.E_RABToBeSetupListCtxtSUReq.list, e_rab_tobesetup_item);
  }
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_UESecurityCapabilities;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UESecurityCapabilities;

  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.buf = (uint8_t *) calloc(1, 2);
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.buf[0] = ((uint8_t *) & conn_est_cnf_pP->ue_security_capabilities_encryption_algorithms)[0];
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.buf[1] = ((uint8_t *) & conn_est_cnf_pP->ue_security_capabilities_encryption_algorithms)[1];
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.size = 2;
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.bits_unused = 0;
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.buf = (uint8_t *) calloc(1, 2);
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.buf[0] = ((uint8_t *) & conn_est_cnf_pP->ue_security_capabilities_integrity_algorithms)[0];
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.buf[1] = ((uint8_t *) & conn_est_cnf_pP->ue_security_capabilities_integrity_algorithms)[1];
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.size = 2;
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.bits_unused = 0;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", conn_est_cnf_pP->ue_security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n", conn_est_cnf_pP->ue_security_capabilities_integrity_algorithms);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_SecurityKey;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_SecurityKey;
  if (conn_est_cnf_pP->kenb) {
    ie->value.choice.SecurityKey.buf = calloc (AUTH_KENB_SIZE, sizeof(uint8_t));
    memcpy (ie->value.choice.SecurityKey.buf, conn_est_cnf_pP->kenb, AUTH_KENB_SIZE);
    ie->value.choice.SecurityKey.size = AUTH_KENB_SIZE;
  } else {
    OAILOG_DEBUG (LOG_S1AP, "No kenb\n");
    ie->value.choice.SecurityKey.buf = NULL;
    ie->value.choice.SecurityKey.size = 0;
  }
  ie->value.choice.SecurityKey.bits_unused = 0;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* optional */
  /*
   * Only add capability information if it's not empty.
   */
  if (conn_est_cnf_pP->ue_radio_cap_length) {
    OAILOG_DEBUG (LOG_S1AP, "UE radio capability found, adding to message\n");

    ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_UERadioCapability;
    ie->criticality = S1AP_Criticality_ignore;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UERadioCapability;
    OCTET_STRING_fromBuf(&ie->value.choice.UERadioCapability,
                        (const char*) conn_est_cnf_pP->ue_radio_capabilities,
                         conn_est_cnf_pP->ue_radio_cap_length);
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
    free_wrapper((void**) &(conn_est_cnf_pP->ue_radio_capabilities));
  }

  if (s1ap_mme_encode_pdu (&pdu, &buffer_p, &length) < 0) {
    // TODO: handle something
    OAILOG_ERROR (LOG_S1AP, "Failed to encode initial context setup request message\n");
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_INITIAL_CONTEXT_SETUP_REQUEST message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 InitialContextSetup/initiatingMessage mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas length %u",
                      (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id,
                      conn_est_cnf_pP->nas_conn_est_cnf.nas_msg ? conn_est_cnf_pP->nas_conn_est_cnf.nas_msg->slen : 0);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
}

#define TODO_S1AP 1
//------------------------------------------------------------------------------
void
s1ap_handle_path_switch_req_ack(
  const itti_s1ap_path_switch_request_ack_t * const path_switch_req_ack_pP)
{
#if TODO_S1AP
  return;
#else
  /*
   * We received modify bearer response from S-GW on S11 interface abstraction.
   * It could be a handover case where we need to respond with the path switch reply to eNB.
   */
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  S1AP_PathSwitchRequestAcknowledgeIEs_t *pathSwitchRequestAcknowledge_p = NULL;

  S1AP_NAS_PDU_t                          nas_pdu = {0}; // yes, alloc on stack
  s1ap_message                            message = {0}; // yes, alloc on stack

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (path_switch_req_ack_pP != NULL);

   ue_ref = s1ap_is_ue_mme_id_in_list (path_switch_req_ack_pP->ue_id);
  if (!ue_ref) {
    OAILOG_ERROR (LOG_S1AP, "This mme ue s1ap id (" MME_UE_S1AP_ID_FMT ") is not attached to any UE context\n", path_switch_req_ack_pP->ue_id);
    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /*
   * Start the outcome response timer.
   * * * * When time is reached, MME consider that procedure outcome has failed.
   */
  //     timer_setup(mme_config.s1ap_config.outcome_drop_timer_sec, 0, TASK_S1AP, INSTANCE_DEFAULT,
  //                 TIMER_ONE_SHOT,
  //                 NULL,
  //                 &ue_ref->outcome_response_timer_id);
  /*
   * Insert the timer in the MAP of mme_ue_s1ap_id <-> timer_id
   */
  //     s1ap_timer_insert(ue_ref->mme_ue_s1ap_id, ue_ref->outcome_response_timer_id);
  // todo: PSR if the state is handover, else just complete the message!
  message.procedureCode = S1AP_ProcedureCode_id_PathSwitchRequest;
  message.direction = S1AP_PDU_PR_successfulOutcome;
  pathSwitchRequestAcknowledge_p = &message.msg.s1ap_PathSwitchRequestAcknowledgeIEs;
  pathSwitchRequestAcknowledge_p->mme_ue_s1ap_id = (unsigned long)ue_ref->mme_ue_s1ap_id;
  pathSwitchRequestAcknowledge_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;

  /* Set the GTP-TEID. This is the S1-U S-GW TEID. */
//  hash_table_ts_t * bearer_contexts_p = (hash_table_ts_t*)path_switch_req_ack_pP->bearer_ctx_to_be_switched_list.bearer_ctxs;
//  bearer_context_t * bearer_context_p = NULL;
//  hashtable_ts_get ((hash_table_ts_t * const)bearer_contexts_p, (const hash_key_t)5, (void **)&bearer_context_p);
//  uint                                    offset = 0;
//  S1AP_E_RABToBeSwitchedULItem_t          e_RABToBeSwitchedUl = {0}; // yes, alloc on stack
  /** Add the new forwarding IEs. */
  if(path_switch_req_ack_pP->bearer_ctx_to_be_switched_list){
    S1AP_IE_t *s1ap_ie_array[path_switch_req_ack_pP->bearer_ctx_to_be_switched_list->num_bearer_context];
    if(path_switch_req_ack_pP->bearer_ctx_to_be_switched_list){
      for(int num_bc = 0; num_bc < path_switch_req_ack_pP->bearer_ctx_to_be_switched_list->num_bearer_context; num_bc++){
        struct S1AP_E_RABToBeSwitchedULItem ie_ul;
        uint8_t ipv4_addr[4];

        memset(&ie_ul, 0, sizeof(struct S1AP_E_RABToBeSwitchedULItem));
        memset(&ipv4_addr, 0, sizeof(ipv4_addr));

        ie_ul.e_RAB_ID = path_switch_req_ack_pP->bearer_ctx_to_be_switched_list->bearer_contexts[num_bc].eps_bearer_id;

        GTP_TEID_TO_ASN1(path_switch_req_ack_pP->bearer_ctx_to_be_switched_list->bearer_contexts[num_bc].s1u_sgw_fteid.teid, &ie_ul.gTP_TEID);
        ie_ul.transportLayerAddress.buf = ipv4_addr;
        memcpy(ie_ul.transportLayerAddress.buf, (uint32_t*)&path_switch_req_ack_pP->bearer_ctx_to_be_switched_list->bearer_contexts[num_bc].s1u_sgw_fteid.ipv4_address.s_addr, 4);
        ie_ul.transportLayerAddress.bits_unused = 0;
        ie_ul.transportLayerAddress.size = 4;

        s1ap_ie_array[num_bc] = s1ap_new_ie(S1AP_ProtocolIE_ID_id_E_RABToBeSwitchedULItem,
            S1AP_Criticality_ignore,
            &asn_DEF_S1AP_E_RABToBeSwitchedULItem,
            &ie_ul);

        ASN_SEQUENCE_ADD(&pathSwitchRequestAcknowledge_p->e_RABToBeSwitchedULList.s1ap_E_RABToBeSwitchedULItem, s1ap_ie_array[num_bc]);

      }
      pathSwitchRequestAcknowledge_p->presenceMask |= S1AP_PATHSWITCHREQUESTACKNOWLEDGEIES_E_RABTOBESWITCHEDULLIST_PRESENT;
    }
  }


  // todo: check if key exists :)
  pathSwitchRequestAcknowledge_p->securityContext.nextHopChainingCount = path_switch_req_ack_pP->ncc;
  pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.buf  = calloc (32, sizeof(uint8_t));
  memcpy (pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.buf, path_switch_req_ack_pP->nh, 32);
  pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.size = 32;


//pathSwitchRequestAcknowledge_p = &message.msg.s1ap_PathSwitchRequestAcknowledgeIEs;

//  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_encryption_algorithms);
//  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_integrity_algorithms);

//  if (conn_est_cnf_pP->kenb) {
//    initialContextSetupRequest_p->securityKey.buf = calloc (32, sizeof(uint8_t));
//    memcpy (initialContextSetupRequest_p->securityKey.buf, conn_est_cnf_pP->kenb, 32);
//    initialContextSetupRequest_p->securityKey.size = 32;
//  } else {
//    OAILOG_DEBUG (LOG_S1AP, "No kenb\n");
//    initialContextSetupRequest_p->securityKey.buf = NULL;
//    initialContextSetupRequest_p->securityKey.size = 0;
//  }

  pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.bits_unused = 0;

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    // TODO: handle something
    DevMessage ("Failed to encode path switch acknowledge message\n");
  }

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_PATH_SWITCH_ACKNOWLEDGE message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->eNB_UE_S1AP_ID);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 PathSwitchAcknowledge/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas length %u",
                      (mme_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->eNB_UE_S1AP_ID, nas_pdu.size);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);

  /** Set the new state as connected. */
  ue_ref->s1_ue_state = S1AP_UE_CONNECTED;

  OAILOG_FUNC_OUT (LOG_S1AP);
#endif
}


int s1ap_handle_handover_preparation_failure (
    const itti_s1ap_handover_preparation_failure_t *handover_prep_failure_pP)
{
  DevAssert(handover_prep_failure_pP);
  return s1ap_handover_preparation_failure (handover_prep_failure_pP->assoc_id, handover_prep_failure_pP->mme_ue_s1ap_id, handover_prep_failure_pP->enb_ue_s1ap_id, handover_prep_failure_pP->cause);
}

int s1ap_handover_preparation_failure (
    const sctp_assoc_id_t assoc_id,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id,
    const S1AP_Cause_PR cause_type)
{
#if TODO_S1AP
  return RETURNerror;
#else
  int                                     enc_rval = 0;
  S1AP_HandoverPreparationFailureIEs_t   *handoverPreparationFailure_p = NULL;
  s1ap_message                            message = { 0 };
  uint8_t                                *buffer = NULL;
  uint32_t                                length = 0;
  int                                     rc = RETURNok;

  /*
   * Mandatory IEs:
   * S1ap-MME-UE-S1AP-ID
   * S1ap-ENB-UE-S1AP-ID
   * S1ap-Cause
   */

  OAILOG_FUNC_IN (LOG_S1AP);


  enb_description_t * source_enb_ref = s1ap_is_enb_assoc_id_in_list(assoc_id);
  if(!source_enb_ref){
    OAILOG_ERROR (LOG_S1AP, "No source-enb could be found for assoc-id %u. Handover Preparation Failure Failed. \n",
        assoc_id);
    /** No need to change anything. */
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  handoverPreparationFailure_p = &message.msg.s1ap_HandoverPreparationFailureIEs;
  s1ap_mme_set_cause(&handoverPreparationFailure_p->cause, S1AP_Cause_PR_misc, 0);
  handoverPreparationFailure_p->eNB_UE_S1AP_ID = enb_ue_s1ap_id;
  handoverPreparationFailure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;

  message.procedureCode = S1AP_ProcedureCode_id_HandoverPreparation;
  message.direction = S1AP_PDU_PR_unsuccessfulOutcome;
  enc_rval = s1ap_mme_encode_pdu (&message, &buffer, &length);

  // Failed to encode
  if (enc_rval < 0) {
    DevMessage ("Failed to encode handover preparation failure message\n");
  }

  bstring b = blk2bstr(buffer, length);
  free(buffer);
  rc = s1ap_mme_itti_send_sctp_request (&b, assoc_id, 0, INVALID_MME_UE_S1AP_ID);
  /**
   * No need to free it, since it is stacked and nothing is allocated.
   * S1AP UE Reference will stay as it is. If removed, it needs to be removed with a separate NAS_IMPLICIT_DETACH.
   */
  OAILOG_FUNC_RETURN (LOG_S1AP, rc);
#endif
}


int s1ap_handle_path_switch_request_failure (
    const itti_s1ap_path_switch_request_failure_t *path_switch_request_failure_pP)
{
  DevAssert(path_switch_request_failure_pP);
  return s1ap_path_switch_request_failure (path_switch_request_failure_pP->assoc_id, path_switch_request_failure_pP->mme_ue_s1ap_id, path_switch_request_failure_pP->enb_ue_s1ap_id, path_switch_request_failure_pP->cause);
}

int s1ap_path_switch_request_failure (
    const sctp_assoc_id_t assoc_id,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id,
    const S1AP_Cause_PR cause_type)
{
#if TODO_S1AP
  return RETURNerror;
#else
  int                                     enc_rval = 0;
  S1AP_PathSwitchRequestFailureIEs_t     *pathSwitchRequestFailure_p = NULL;
  s1ap_message                            message = { 0 };
  uint8_t                                *buffer = NULL;
  uint32_t                                length = 0;
  int                                     rc = RETURNok;

  /*
   * Mandatory IEs:
   * S1ap-MME-UE-S1AP-ID
   * S1ap-ENB-UE-S1AP-ID
   * S1ap-Cause
   */

  OAILOG_FUNC_IN (LOG_S1AP);

  pathSwitchRequestFailure_p = &message.msg.s1ap_PathSwitchRequestFailureIEs;
  s1ap_mme_set_cause(&pathSwitchRequestFailure_p->cause, cause_type, 4);
  pathSwitchRequestFailure_p->eNB_UE_S1AP_ID = enb_ue_s1ap_id;
  pathSwitchRequestFailure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;

  message.procedureCode = S1AP_ProcedureCode_id_PathSwitchRequest;
  message.direction = S1AP_PDU_PR_unsuccessfulOutcome;
  enc_rval = s1ap_mme_encode_pdu (&message, &buffer, &length);

  // Failed to encode
  if (enc_rval < 0) {
    DevMessage ("Failed to encode path switch request failure message\n");
  }

  bstring b = blk2bstr(buffer, length);
  free(buffer);
  rc = s1ap_mme_itti_send_sctp_request (&b, assoc_id, 0, INVALID_MME_UE_S1AP_ID);
  /**
   * No need to free it, since it is stacked and nothing is allocated.
   * S1AP UE Reference will stay as it is. If removed, it needs to be removed with a separate NAS_IMPLICIT_DETACH.
   */
  OAILOG_FUNC_RETURN (LOG_S1AP, rc);
#endif
}

void
s1ap_handle_handover_cancel_acknowledge (
  const itti_s1ap_handover_cancel_acknowledge_t* const handover_cancel_acknowledge_pP)
{
#if TODO_S1AP
  return;
#else
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *source_enb_ref = NULL;
  S1AP_HandoverCancelAcknowledgeIEs_t    *handoverCancelAcknowledge_p = NULL;

  s1ap_message                            message = {0}; // yes, alloc on stack
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (handover_cancel_acknowledge_pP != NULL);

  source_enb_ref = s1ap_is_enb_assoc_id_in_list(handover_cancel_acknowledge_pP->assoc_id);
  if(!source_enb_ref){
    OAILOG_ERROR (LOG_S1AP, "No source-enb could be found for assoc-id %u. Handover Cancel Ack Failed. \n",
        handover_cancel_acknowledge_pP->assoc_id);
    /** No need to change anything. */
    OAILOG_FUNC_OUT (LOG_S1AP);
  }
  ue_ref = s1ap_is_ue_enb_id_in_list(source_enb_ref, handover_cancel_acknowledge_pP->enb_ue_s1ap_id);
  if (!ue_ref) {
    /**
     * The source UE-Reference should exist.
     * It is an error, if its not existing.
     * We rely on the timer that if no HANDOVER_NOTIFY is received in time, we will remove the UE context implicitly and the target-enb UE_REFERENCE.
     */
    OAILOG_ERROR (LOG_S1AP, " NO UE_CONTEXT could be found to send handover cancel acknowledge for UE enb ue s1ap id (" ENB_UE_S1AP_ID_FMT ") to the source eNB with assocId %d. \n",
        handover_cancel_acknowledge_pP->enb_ue_s1ap_id, handover_cancel_acknowledge_pP->assoc_id);
    OAILOG_FUNC_OUT (LOG_S1AP);
  }
  /**
   * No timer needs to be started here.
   * The only timer is in the source-eNB..
   */
   message.procedureCode = S1AP_ProcedureCode_id_HandoverCancel;
   message.direction = S1AP_PDU_PR_successfulOutcome;
   handoverCancelAcknowledge_p = &message.msg.s1ap_HandoverCancelAcknowledgeIEs;
   /** Set the enb_ue_s1ap id and the mme_ue_s1ap_id. */
   handoverCancelAcknowledge_p->mme_ue_s1ap_id = (unsigned long)ue_ref->mme_ue_s1ap_id;
   handoverCancelAcknowledge_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;

   if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode handover cancel acknowledge \n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_HANDOVER_CANCEL_ACKNOWLEDGE message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)handoverCancelAcknowledge_p->mme_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      0,
                      NULL, 0,
                      "0 HandoverCancelAcknowledge/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)handoverCancelAcknowledge_p->mme_ue_s1ap_id);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  // todo: the next_sctp_stream is the one without incrementation?
  s1ap_mme_itti_send_sctp_request (&b, source_enb_ref->sctp_assoc_id, source_enb_ref->next_sctp_stream, handover_cancel_acknowledge_pP->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
#endif
}

void
s1ap_handle_handover_request (
  const itti_s1ap_handover_request_t * const handover_request_pP)
{
#if TODO_S1AP
  return;
#else
  /*
   * We received as a consequence of S1AP handover a bearer modification response (CSR or MBR) from S-GW on S11 interface abstraction.
   * We initiate an S1AP handover in the target cell.
   * 1- We will not create a UE_REFERENCE at this step, since we don't have the eNB-ID, yet to set in the UE map of the eNB.
   * We will create it with HANDOVER_REQUEST_ACKNOWLEDGE (success) and set it in the eNB map.
   *
   * 2- We won't set the MME_UE_S1AP_ID's SCTP_ASSOC, yet. We will do it in HANDOVER_NOTIFY, since after then only UE-CONTEXT-RELEASE-COMMAND will be sent to the source eNB.
   * The UE-Context-Release-Command where the MME_UE_S1AP_ID is already overwritten and the UE-Context-Realease-COMPLETE message will be handled where the mme_ue_s1ap_id to sctp_assoc
   * association is already removed.
   */
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *target_enb_ref = NULL;
  S1AP_HandoverRequestIEs_t              *handoverRequest_p = NULL;

  s1ap_message                            message = {0}; // yes, alloc on stack
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (handover_request_pP != NULL);

  /*
   * Based on the MME_UE_S1AP_ID, you may or may not have a UE reference, we don't care. Just send HO_Request to the new eNB.
   * Check that there exists an enb reference to the target-enb.
   */
  target_enb_ref = s1ap_is_enb_id_in_list(handover_request_pP->macro_enb_id);
  if(!target_enb_ref){
    OAILOG_ERROR (LOG_S1AP, "No target-enb could be found for enb-id %u. Handover Failed. \n",
            handover_request_pP->macro_enb_id);
    /**
     * Send Handover Failure back (manually) to the MME.
     * This will trigger an implicit detach if the UE is not REGISTERED yet (single MME S1AP HO), or will just send a HO-PREP-FAILURE to the MME (if the cause is not S1AP-SYSTEM-FAILURE).
     */
    message_p = itti_alloc_new_message (TASK_S1AP, S1AP_HANDOVER_FAILURE);
    AssertFatal (message_p != NULL, "itti_alloc_new_message Failed");
    itti_s1ap_handover_failure_t *handover_failure_p = &message_p->ittiMsg.s1ap_handover_failure;
    memset ((void *)&message_p->ittiMsg.s1ap_handover_failure, 0, sizeof (itti_s1ap_handover_failure_t));
    /** Fill the S1AP Handover Failure elements per hand. */
    handover_failure_p->mme_ue_s1ap_id = handover_request_pP->ue_id;
    /** No need to remove any UE_Reference to the target_enb, not existing. */
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /**
   * UE Reference will only be created with a valid ENB_UE_S1AP_ID!
   * We don't wan't to save 2 the UE reference twice in the hashmap, but only with a valid ENB_ID key.
   * That's why create the UE Reference only with Handover Request Acknowledge.
   * No timer will be created for Handover Request (not defined in the specification and no UE-Reference to the target-ENB exists yet.
   *
   * Target eNB could be found. Create a new ue_reference.
   * This UE eNB Id has currently no known s1 association.
   * * * * Create new UE context by associating new mme_ue_s1ap_id.
   * * * * Update eNB UE list.
   *
   * todo: what to provide as enb_id?
   */

  /*
   * Start the outcome response timer.
   *
   * * * * When time is reached, MME consider that procedure outcome has failed.
   */
  //     timer_setup(mme_config.s1ap_config.outcome_drop_timer_sec, 0, TASK_S1AP, INSTANCE_DEFAULT,
  //                 TIMER_ONE_SHOT,
  //                 NULL,
  //                 &ue_ref->outcome_response_timer_id);
  /*
   * Insert the timer in the MAP of mme_ue_s1ap_id <-> timer_id
   */
  //     s1ap_timer_insert(ue_ref->mme_ue_s1ap_id, ue_ref->outcome_response_timer_id);
  // todo: PSR if the state is handover, else just complete the message!
  message.procedureCode = S1AP_ProcedureCode_id_HandoverResourceAllocation;
  message.direction = S1AP_PDU_PR_initiatingMessage;
  handoverRequest_p = &message.msg.s1ap_HandoverRequestIEs;
  handoverRequest_p->mme_ue_s1ap_id = (unsigned long)handover_request_pP->ue_id;

  S1AP_E_RABToBeSetupItemHOReq_t          e_RABToBeSetupHO[handover_request_pP->bearer_ctx_to_be_setup_list->num_bearer_context]; // yes, alloc on stack
  memset(e_RABToBeSetupHO, 0, sizeof(e_RABToBeSetupHO));
  // todo: only a single bearer assumed right now.
  s1ap_add_bearer_context_to_setup_list(&handoverRequest_p->e_RABToBeSetupListHOReq, &e_RABToBeSetupHO, handover_request_pP->bearer_ctx_to_be_setup_list);
  // e_RABToBeSetupHO --> todo: disappears inside

  /** Set the security context. */
  handoverRequest_p->securityContext.nextHopChainingCount = handover_request_pP->ncc;
  handoverRequest_p->securityContext.nextHopParameter.buf  = calloc (32, sizeof(uint8_t));
  memcpy (handoverRequest_p->securityContext.nextHopParameter.buf, handover_request_pP->nh, 32);
  handoverRequest_p->securityContext.nextHopParameter.size = 32;
  handoverRequest_p->securityContext.nextHopParameter.bits_unused = 0;

  /** Add the security capabilities. */
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", handover_request_pP->security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n" , handover_request_pP->security_capabilities_integrity_algorithms);

  handoverRequest_p->ueSecurityCapabilities.encryptionAlgorithms.buf                  = (uint8_t *) & handover_request_pP->security_capabilities_encryption_algorithms;
  handoverRequest_p->ueSecurityCapabilities.encryptionAlgorithms.size                 = 2;
  handoverRequest_p->ueSecurityCapabilities.encryptionAlgorithms.bits_unused          = 0;
  handoverRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.buf         = (uint8_t *) & handover_request_pP->security_capabilities_integrity_algorithms;
  handoverRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.size        = 2;
  handoverRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.bits_unused = 0;
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", handover_request_pP->security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n", handover_request_pP->security_capabilities_integrity_algorithms);

  /** Set Handover Type. */
  handoverRequest_p->handoverType = S1AP_HandoverType_intralte;

  /** Set Id-Cause. */
  handoverRequest_p->cause.present = S1AP_Cause_PR_radioNetwork;
  handoverRequest_p->cause.choice.radioNetwork = S1AP_CauseRadioNetwork_handover_desirable_for_radio_reason;

  /*
   * uEaggregateMaximumBitrateDL and uEaggregateMaximumBitrateUL expressed in term of bits/sec
   */
  asn_uint642INTEGER (&handoverRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateDL, handover_request_pP->ambr.br_dl);
  asn_uint642INTEGER (&handoverRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateUL, handover_request_pP->ambr.br_ul);

  /*
   * E-UTRAN Target-ToSource Transparent Container.
   */
  OCTET_STRING_fromBuf(&handoverRequest_p->source_ToTarget_TransparentContainer,
      handover_request_pP->source_to_target_eutran_container->data, blength(handover_request_pP->source_to_target_eutran_container));
  /** bstring of message will be destroyed outside of the ITTI message handler. */

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode handover command \n");
    /** We rely on the handover_notify timeout to remove the UE context. */
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  // todo: s1ap_generate_initiating_message will remove the things?

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_HANDOVER_REQUEST message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)handoverRequest_p->mme_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      0,
                      NULL, 0,
                      "0 HandoverRequest/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)handoverRequest_p->mme_ue_s1ap_id);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  // todo: the next_sctp_stream is the one without incrementation?
  s1ap_mme_itti_send_sctp_request (&b, target_enb_ref->sctp_assoc_id, target_enb_ref->next_sctp_stream, handover_request_pP->ue_id);

  /*
   * Leave the state in as it is.
   * Not creating a UE-Reference towards the target-ENB.
   */
  OAILOG_FUNC_OUT (LOG_S1AP);
#endif
}

/*
static
S1AP_IE_t * s1ap_generate_bearer_to_forward(S1AP_E_RABDataForwardingItem_t *ie_ul, bearer_context_created_t *bc_to_forward){

  ie_ul->e_RAB_ID = 8;

//  ie_ul.uL_TransportLayerAddress = calloc(1, sizeof (S1AP_TransportLayerAddress_t));


  GTP_TEID_TO_ASN1(0x11223344, ie_ul->uL_GTP_TEID);
  ie_ul->uL_TransportLayerAddress->buf[0] = 0xC0;
  ie_ul->uL_TransportLayerAddress->buf[1] = 0xA8;
  ie_ul->uL_TransportLayerAddress->buf[2] = 0x0F;
  ie_ul->uL_TransportLayerAddress->buf[3] = 0x0A;
  ie_ul->uL_TransportLayerAddress->bits_unused = 0;
  ie_ul->uL_TransportLayerAddress->size = 4;

  S1AP_IE_t *s1ap_ie = s1ap_new_ie(S1AP_ProtocolIE_ID_id_E_RABDataForwardingItem,
      S1AP_Criticality_ignore,
      &asn_DEF_S1AP_E_RABDataForwardingItem,
      &ie_ul);
  return s1ap_ie;
}
*/

/**
 * Informing the source eNodeB about the successfully established handover.
 * Send the handover command to the source enb via the old s1ap ue_reference.
 * Keeping the old s1ap ue_reference for enb/MME status transfer.
 */
void
s1ap_handle_handover_command (
  const itti_s1ap_handover_command_t * const handover_command_pP)
{
#if TODO_S1AP
  return;
#else
  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *target_enb_ref = NULL;
  S1AP_HandoverCommandIEs_t              *handoverCommand_p = NULL;

  s1ap_message                            message = {0}; // yes, alloc on stack

  enb_description_t                      *enb_ref = NULL;

  enb_ref = s1ap_is_enb_id_in_list(handover_command_pP->enb_id);
  if(!enb_ref){
    enb_ref = s1ap_is_enb_id_in_list(10);
    enb_ref = s1ap_is_enb_id_in_list(256);
  }

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (handover_command_pP != NULL);

  /**
   * Get the UE_REFERENCE structure via the received eNB_ID and enb_ue_s1ap_id pairs.
   * Currently, it may be that its a too early handover back and we have both ue_references.
   */
  ue_ref = s1ap_is_enb_ue_s1ap_id_in_list_per_enb(handover_command_pP->enb_ue_s1ap_id, handover_command_pP->enb_id);
  if (!ue_ref) {
    /**
     * The source UE-Reference should exist.
     * It is an error, if its not existing.
     * We rely on the timer that if no HANDOVER_NOTIFY is received in time, we will remove the UE context implicitly and the target-enb UE_REFERENCE.
     */
    OAILOG_ERROR (LOG_S1AP, " NO UE_CONTEXT could be found to send handover command for UE mme ue s1ap id (" MME_UE_S1AP_ID_FMT ") to the source eNB with eNBId %d. \n",
        handover_command_pP->mme_ue_s1ap_id, handover_command_pP->enb_id);
    OAILOG_FUNC_OUT (LOG_S1AP);
  }
  /**
   * No timer needs to be started here.
   * The only timer is in the source-eNB..
   */
  // todo: PSR if the state is handover, else just complete the message!
  message.procedureCode = S1AP_ProcedureCode_id_HandoverPreparation;
  message.direction = S1AP_PDU_PR_successfulOutcome;
  handoverCommand_p = &message.msg.s1ap_HandoverCommandIEs;
  /** Set the enb_ue_s1ap id and the mme_ue_s1ap_id. */
  handoverCommand_p->mme_ue_s1ap_id = (unsigned long)ue_ref->mme_ue_s1ap_id;
  handoverCommand_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;
  /** Set the handover type. */
  handoverCommand_p->handoverType = S1AP_HandoverType_intralte;
  /*
   * E-UTRAN Target-ToSource Transparent Container.
   * todo: Lionel: ask if correct:
   * The octet string will be freed inside: .
   *  s1ap_generate_successfull_outcome (
       * We can safely free list of IE from sptr
      ASN_STRUCT_FREE_CONTENTS_ONLY (*td, sptr);
   */

  /** Add the new forwarding IEs. */
  S1AP_IE_t *s1ap_ie_array[handover_command_pP->bearer_ctx_to_be_forwarded_list->num_bearer_context];
  if(handover_command_pP->bearer_ctx_to_be_forwarded_list){
      for(int num_bc = 0; num_bc < handover_command_pP->bearer_ctx_to_be_forwarded_list->num_bearer_context; num_bc++){
        struct S1AP_E_RABDataForwardingItem ie_ul;
        S1AP_GTP_TEID_t ul_gtp_teid;
        S1AP_TransportLayerAddress_t uL_TransportLayerAddress;
        uint8_t ipv4_addr[4];

        memset(&ul_gtp_teid, 0, sizeof(S1AP_GTP_TEID_t));
        memset(&ie_ul, 0, sizeof(struct S1AP_E_RABDataForwardingItem));
        memset(&uL_TransportLayerAddress, 0, sizeof(S1AP_TransportLayerAddress_t));
        memset(&ipv4_addr, 0, sizeof(ipv4_addr));

        ie_ul.e_RAB_ID = handover_command_pP->bearer_ctx_to_be_forwarded_list->bearer_contexts[num_bc].eps_bearer_id;
        ie_ul.uL_GTP_TEID = &ul_gtp_teid;

        GTP_TEID_TO_ASN1(handover_command_pP->bearer_ctx_to_be_forwarded_list->bearer_contexts[num_bc].s1u_sgw_fteid.teid, ie_ul.uL_GTP_TEID);
        ie_ul.uL_TransportLayerAddress = &uL_TransportLayerAddress;
        ie_ul.uL_TransportLayerAddress->buf = ipv4_addr;
        memcpy(ie_ul.uL_TransportLayerAddress->buf, (uint32_t*)&handover_command_pP->bearer_ctx_to_be_forwarded_list->bearer_contexts[num_bc].s1u_sgw_fteid.ipv4_address.s_addr, 4);
        ie_ul.uL_TransportLayerAddress->bits_unused = 0;
        ie_ul.uL_TransportLayerAddress->size = 4;

        s1ap_ie_array[num_bc] = s1ap_new_ie(S1AP_ProtocolIE_ID_id_E_RABDataForwardingItem,
            S1AP_Criticality_ignore,
            &asn_DEF_S1AP_E_RABDataForwardingItem,
            &ie_ul);

        ASN_SEQUENCE_ADD(&handoverCommand_p->e_RABSubjecttoDataForwardingList.s1ap_E_RABDataForwardingItem, s1ap_ie_array[num_bc]);

      }
      handoverCommand_p->presenceMask |= S1AP_HANDOVERCOMMANDIES_E_RABSUBJECTTODATAFORWARDINGLIST_PRESENT;
  }

  OCTET_STRING_fromBuf(&handoverCommand_p->target_ToSource_TransparentContainer,
      handover_command_pP->eutran_target_to_source_container->data, blength(handover_command_pP->eutran_target_to_source_container));

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    DevMessage("Failed to encode handover command \n");
  }

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_HANDOVER_COMMAND message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)handoverCommand_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)handoverCommand_p->eNB_UE_S1AP_ID);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 HandoverCommand/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)handoverCommand_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)handoverCommand_p->eNB_UE_S1AP_ID);
  bstring b = blk2bstr(buffer_p, length);

  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  free(buffer_p);

  for(int num_bc = 0; num_bc < handover_command_pP->bearer_ctx_to_be_forwarded_list->num_bearer_context; num_bc++){
    free_wrapper(&s1ap_ie_array[num_bc]);
  }
  /** Not changing the ECM state of the source eNB UE-Reference. */
  OAILOG_FUNC_OUT (LOG_S1AP);
#endif
}


//------------------------------------------------------------------------------
void
s1ap_handle_mme_status_transfer( const itti_s1ap_status_transfer_t * const s1ap_status_transfer_pP)
{
#if TODO_S1AP
  return;
#else
  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *target_enb_ref = NULL;
  S1AP_MMEStatusTransferIEs_t            *mmeStatusTransfer_p = NULL;

  s1ap_message                            message = {0}; // yes, alloc on stack

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (s1ap_status_transfer_pP != NULL);

  /**
   * Find the UE-Reference based on the enb_ue_s1ap_id.
   * We did not register the mme_ue_s1ap_id, yet.
   */
  ue_ref = s1ap_is_enb_ue_s1ap_id_in_list_per_enb(s1ap_status_transfer_pP->enb_ue_s1ap_id, s1ap_status_transfer_pP->enb_id);
  if (!ue_ref) {
    /** Set the source_assoc_id!! */
    OAILOG_WARNING(LOG_S1AP, " NO UE_CONTEXT could be found to send MME Status Transfer UE with enb ue s1ap id (" ENB_UE_S1AP_ID_FMT ") and eNB-ID %d. UE contexts are assumed to be cleaned up via timer or handover notify already happened. Checking with ueId " MME_UE_S1AP_ID_FMT ". \n",
        s1ap_status_transfer_pP->enb_ue_s1ap_id, s1ap_status_transfer_pP->enb_id, s1ap_status_transfer_pP->mme_ue_s1ap_id);

    ue_ref = s1ap_is_ue_mme_id_in_list(s1ap_status_transfer_pP->mme_ue_s1ap_id);
    if(!ue_ref){
      OAILOG_ERROR(LOG_S1AP, " Could not find S1AP UE context also with MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT " to send MME_STATUS_TRANSFER. \n", s1ap_status_transfer_pP->mme_ue_s1ap_id);
      OAILOG_FUNC_OUT (LOG_S1AP);
    }
    OAILOG_WARNING(LOG_S1AP, " FOUND S1AP UE context with MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT " to send MME_STATUS_TRANSFER (assuming HO_NOTIFY already happened). \n", s1ap_status_transfer_pP->mme_ue_s1ap_id);
  }
  /** Create the MME S1AP Statut Transfer message. */
  message.procedureCode = S1AP_ProcedureCode_id_MMEStatusTransfer;
  message.direction = S1AP_PDU_PR_initiatingMessage;
  mmeStatusTransfer_p = &message.msg.s1ap_MMEStatusTransferIEs;

  /** Set the enb_ue_s1ap id and the mme_ue_s1ap_id. */
  mmeStatusTransfer_p->mme_ue_s1ap_id = (unsigned long)s1ap_status_transfer_pP->mme_ue_s1ap_id;
  mmeStatusTransfer_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;

  /*
   * E-UTRAN Status-Transfer Source Transparent Container.
   */
  // Add a new element.
  S1AP_IE_t                               status_container;
  ssize_t                                 encoded;

  memset (&status_container, 0, sizeof (S1AP_IE_t));
  status_container.id = S1AP_ProtocolIE_ID_id_Bearers_SubjectToStatusTransfer_Item;
  status_container.criticality = S1AP_Criticality_ignore;

  /*
   * E-UTRAN Target-ToSource Transparent Container.
   */

  /**
   * todo: lionel:
   * Here, do we need to allocate an OCTET String container because of the purge of the message in the encode?
   * Or can we use this?
   * What is exactly purged in the encoder? The list (without the contents)? the contents of the list? contents & list?
   */
  status_container.value.buf  = s1ap_status_transfer_pP->bearerStatusTransferList_buffer->data + 6;
  status_container.value.size = blength(s1ap_status_transfer_pP->bearerStatusTransferList_buffer) - 6; // s1ap_status_transfer_pP->bearerStatusTransferList_buffer->slen;

  /** Adding stacked value. */
  ASN_SEQUENCE_ADD (&mmeStatusTransfer_p->eNB_StatusTransfer_TransparentContainer.bearers_SubjectToStatusTransferList, &status_container);

  /** Encoding without allocating? */
  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode MME status transfer. \n");
    /** We rely on the handover_notify timeout to remove the UE context. */
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  // todo: do we need this destroy?
  bdestroy_wrapper(&s1ap_status_transfer_pP->bearerStatusTransferList_buffer);
//  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_MME_STATUS_TRANSFER message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
//              (mme_ue_s1ap_id_t)mmeStatusTransfer_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)mmeStatusTransfer_p->eNB_UE_S1AP_ID);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 MmeStatusTransfer/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)mmeStatusTransfer_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)mmeStatusTransfer_p->eNB_UE_S1AP_ID);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, s1ap_status_transfer_pP->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
#endif
}

//------------------------------------------------------------------------------
void
s1ap_handle_paging (const itti_s1ap_paging_t * const s1ap_paging_pP)
{

  uint32_t                                length = 0;
  S1AP_S1AP_PDU_t                         pdu = {0};
  S1AP_Paging_t                          *out = NULL;
  uint8_t                                *buffer_p = NULL;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *eNB_ref = NULL;
  S1AP_PagingIEs_t                       *ie = NULL;


  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (s1ap_paging_pP != NULL);

  ue_ref = s1ap_is_ue_mme_id_in_list (s1ap_paging_pP->mme_ue_s1ap_id);
  if (ue_ref) {
    /** Set the source_assoc_id!! */
    /** todo: for intra-mme handover, this will deliver the old s1ap id. */
    OAILOG_ERROR (LOG_S1AP, " UE_CONTEXT already exist. Cannot page UE mme ue s1ap id (" MME_UE_S1AP_ID_FMT "). \n",
        s1ap_paging_pP->mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /** Get the last eNB. */
  if ((eNB_ref = s1ap_is_enb_assoc_id_in_list (s1ap_paging_pP->sctp_assoc_id_key)) == NULL) {
    OAILOG_WARNING (LOG_S1AP, "Unknown eNB on assoc_id %d\n", s1ap_paging_pP->sctp_assoc_id_key);
    OAILOG_FUNC_OUT (LOG_S1AP);
  }
  memset(&pdu, 0, sizeof(pdu));
  pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
  pdu.choice.initiatingMessage.procedureCode = S1AP_ProcedureCode_id_Paging;
  pdu.choice.initiatingMessage.criticality = S1AP_Criticality_ignore;
  pdu.choice.initiatingMessage.value.present = S1AP_InitiatingMessage__value_PR_Paging;
  out = &pdu.choice.initiatingMessage.value.choice.Paging;

  /* mandatory */
  ie = (S1AP_PagingIEs_t *)calloc(1, sizeof(S1AP_PagingIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_UEIdentityIndexValue;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_PagingIEs__value_PR_UEIdentityIndexValue;
  ie->value.choice.UEIdentityIndexValue.buf = calloc (2, sizeof(uint8_t));
  memcpy(ie->value.choice.UEIdentityIndexValue.buf, (uint8_t*)&(s1ap_paging_pP->ue_identity_index), 2);
  ie->value.choice.UEIdentityIndexValue.bits_unused = 6;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /** Encode the CN Domain. */
  ie = (S1AP_PagingIEs_t *)calloc(1, sizeof(S1AP_PagingIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_CNDomain;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_PagingIEs__value_PR_CNDomain;
  ie->value.choice.CNDomain = S1AP_CNDomain_ps;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /** Set the UE Paging Identity . */
  ie = (S1AP_PagingIEs_t *)calloc(1, sizeof(S1AP_PagingIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_UEPagingID;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_PagingIEs__value_PR_UEPagingID;
  ie->value.choice.UEPagingID.present = S1AP_UEPagingID_PR_s_TMSI;
  INT32_TO_OCTET_STRING(s1ap_paging_pP->tmsi, &ie->value.choice.UEPagingID.choice.s_TMSI.m_TMSI);
  INT8_TO_OCTET_STRING(mme_config.gummei.gummei[0].mme_code, &ie->value.choice.UEPagingID.choice.s_TMSI.mMEC);
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /** Set the TAI-List. */
  ie = (S1AP_PagingIEs_t *)calloc(1, sizeof(S1AP_PagingIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_TAIList;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_PagingIEs__value_PR_TAIList;


  S1AP_TAIItemIEs_t * tai_item = (S1AP_TAIItemIEs_t *)calloc(1, sizeof(S1AP_TAIItemIEs_t));
  tai_item->id = S1AP_ProtocolIE_ID_id_TAIList;
  tai_item->criticality = S1AP_Criticality_reject;
  tai_item->value.present = S1AP_TAIItemIEs__value_PR_TAIItem;
  INT16_TO_OCTET_STRING(s1ap_paging_pP->tai.tac, &tai_item->value.choice.TAIItem.tAI.tAC);
  /** Set the PLMN. */
  uint8_t                                 plmn[3] = { 0x00, 0x00, 0x00 };     //{ 0x02, 0xF8, 0x29 };
  PLMN_T_TO_TBCD (s1ap_paging_pP->tai.plmn,
                    plmn,
                    mme_config_find_mnc_length(
                        s1ap_paging_pP->tai.plmn.mcc_digit1, s1ap_paging_pP->tai.plmn.mcc_digit2, s1ap_paging_pP->tai.plmn.mcc_digit3,
                        s1ap_paging_pP->tai.plmn.mnc_digit1, s1ap_paging_pP->tai.plmn.mnc_digit2, s1ap_paging_pP->tai.plmn.mnc_digit3)
  );
  OCTET_STRING_fromBuf(&tai_item->value.choice.TAIItem.tAI.pLMNidentity, (const char*)plmn, 3);
  /** Set the TAI. */
  ASN_SEQUENCE_ADD (&ie->value.choice.TAIList.list, &tai_item);

  /** Encoding without allocating? */
  if (s1ap_mme_encode_pdu (&pdu, &buffer_p, &length) < 0) {
    // TODO: handle something
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_PAGING message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " \n",
              (mme_ue_s1ap_id_t)s1ap_paging_pP->mme_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 S1AP Paging/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)s1ap_paging_pP->mme_ue_s1ap_id);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, eNB_ref->sctp_assoc_id, eNB_ref->next_sctp_stream, s1ap_paging_pP->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
}

//------------------------------------------------------------------------------
static
int s1ap_generate_bearer_context_to_setup(bearer_context_to_be_created_t * bc_tbc, S1AP_E_RABToBeSetupItemHOReq_t         *e_RABToBeSetupHO_p)
{
  OAILOG_FUNC_IN (LOG_S1AP);
#if TODO_S1AP
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
#else
  uint                                    offset = 0;

  e_RABToBeSetupHO_p->e_RAB_ID = bc_tbc->eps_bearer_id;

  /** Set QoS parameters of the bearer. */
  e_RABToBeSetupHO_p->e_RABlevelQosParameters.qCI                                                  = bc_tbc->bearer_level_qos.qci;
  e_RABToBeSetupHO_p->e_RABlevelQosParameters.allocationRetentionPriority.priorityLevel            = bc_tbc->bearer_level_qos.pl;
  e_RABToBeSetupHO_p->e_RABlevelQosParameters.allocationRetentionPriority.pre_emptionCapability    = bc_tbc->bearer_level_qos.pci;
  e_RABToBeSetupHO_p->e_RABlevelQosParameters.allocationRetentionPriority.pre_emptionVulnerability = bc_tbc->bearer_level_qos.pvi;

  INT32_TO_OCTET_STRING (bc_tbc->s1u_sgw_fteid.teid, &e_RABToBeSetupHO_p->gTP_TEID);

  /*
   * S-GW IP address(es) for user-plane
   */
  bstring transportLayerAddress = fteid_ip_address_to_bstring(&bc_tbc->s1u_sgw_fteid);

  e_RABToBeSetupHO_p->transportLayerAddress.buf = calloc (blength(transportLayerAddress), sizeof (uint8_t));
  memcpy (e_RABToBeSetupHO_p->transportLayerAddress.buf,
      transportLayerAddress->data,
      blength(transportLayerAddress));
  e_RABToBeSetupHO_p->transportLayerAddress.size = blength(transportLayerAddress);

  // todo: optimize this
  /** Destroy the temporarily allocated bstring. */
  bdestroy_wrapper(&transportLayerAddress);
  // todo: ipv6

  // TODO: S1AP PDU..
  /** Set the bearer as an ASN list element. */
//  S1AP_IE_t                               s1ap_ie_ext;
//  ssize_t                                 encoded;
//  S1AP_PDU_t                              pdu;
//
//  memset (&s1ap_ie_ext, 0, sizeof (S1AP_IE_t));
//  s1ap_ie_ext.id = S1AP_ProtocolIE_ID_id_Data_Forwarding_Not_Possible;
//  s1ap_ie_ext.criticality = S1AP_Criticality_ignore;
//  s1ap_ie_ext.value.buf = NULL;
//  s1ap_ie_ext.value.size = 0;
//  ASN_SEQUENCE_ADD (e_RABToBeSetupHO_p->iE_Extensions, &pdu);
  /** Adding stacked value. */
//
//  if (bearer_ctx_p->s_gw_address.pdn_type == IPv6 ||bearer_ctx_p->s_gw_address.pdn_type == IPv4_AND_v6) {
//    if (bearer_ctx_p->s_gw_address.pdn_type == IPv6) {
//      /*
//       * Only IPv6 supported
//         */
//      /*
//       * TODO: check memory allocation
//       */
//      e_RABToBeSetupHO_p->transportLayerAddress.buf = calloc (16, sizeof (uint8_t));
//    } else {
//      /*
//       * Both IPv4 and IPv6 provided
//       */
//      /*
//       * TODO: check memory allocation
//       */
//      e_RABToBeSetupHO_p->transportLayerAddress.buf = realloc (e_RABToBeSetupHO_p->transportLayerAddress.buf, (16 + offset) * sizeof (uint8_t));
//    }
//
//    memcpy (&e_RABToBeSetupHO_p->transportLayerAddress.buf[offset], bearer_ctx_p->s_gw_address.address.ipv6_address, 16);
//    e_RABToBeSetupHO_p->transportLayerAddress.size = 16 + offset;
//    e_RABToBeSetupHO_p->transportLayerAddress.bits_unused = 0;
//  }

  return RETURNok;
#endif
}

//------------------------------------------------------------------------------
#if TODO_S1AP
#else
static bool
s1ap_add_bearer_context_to_setup_list (S1AP_E_RABToBeSetupListHOReqIEs_t * const e_RABToBeSetupListHOReq_p,
    S1AP_E_RABToBeSetupItemHOReq_t        * e_RABToBeSetupHO_p, bearer_contexts_to_be_created_t * bcs_tbc)
{

  int num_bc = 0;
  for(int num_bc = 0; num_bc < bcs_tbc->num_bearer_context; num_bc++){
    if(s1ap_generate_bearer_context_to_setup(&bcs_tbc->bearer_contexts[num_bc], &e_RABToBeSetupHO_p[num_bc]) != RETURNok){
      OAILOG_ERROR(LOG_S1AP, "Error adding bearer context with ebi %d to list of bearers to setup.\n", bcs_tbc->bearer_contexts[num_bc].eps_bearer_id);
      return false;
    }
    /** Add the E-RAB bearer to the message. */
    ASN_SEQUENCE_ADD (e_RABToBeSetupListHOReq_p, &e_RABToBeSetupHO_p[num_bc]);
  }
  return true;
}
#endif
//static bool
//s1ap_add_bearer_context_to_switch_list (S1AP_E_RABToBeSwitchedULListIEs_t * const e_RABToBeSwitchedListHOReq_p,
//    S1AP_E_RABToBeSwitchedULItem_t        * e_RABToBeSwitchedHO_p, bearer_context_t * bearer_ctxt_p)
//{
//
//  if(s1ap_generate_bearer_context_to_switch(bearer_ctxt_p, e_RABToBeSwitchedHO_p) != RETURNok){
//    OAILOG_ERROR(LOG_S1AP, "Error adding bearer context with ebi %d to list of bearers to switch.\n", bearer_ctxt_p->ebi);
//    return false;
//  }
//  /** Add the E-RAB bearer to the message. */
//  ASN_SEQUENCE_ADD (e_RABToBeSwitchedListHOReq_p, e_RABToBeSwitchedHO_p);
//  return true;
//}


//int s1ap_generate_bearer_context_to_switch(bearer_context_t * bearer_ctx_p, S1AP_E_RABToBeSwitchedULItem_t         * e_RABToBeSwitchedUL_p){
//  OAILOG_FUNC_IN (LOG_S1AP);
//
//  uint                                    offset = 0;
//
//  e_RABToBeSwitchedUL_p->e_RAB_ID = bearer_ctx_p->ebi;
//
//  INT32_TO_OCTET_STRING (bearer_ctx_p->s_gw_teid, &e_RABToBeSwitchedUL_p->gTP_TEID);
//
//  /*
//   * S-GW IP address(es) for user-plane
//   */
//  if(bearer_ctx_p->s_gw_address.address.ipv4_address) {
//    e_RABToBeSwitchedUL_p->transportLayerAddress.buf = calloc(4, sizeof(uint8_t));
//    /*
//     * ONLY IPV4 SUPPORTED
//     */
//    memcpy(e_RABToBeSwitchedUL_p->transportLayerAddress.buf, &bearer_ctx_p->s_gw_address.address.ipv4_address, 4);
//    offset += 4; /**< Later for IPV4V6 addresses. */
//    e_RABToBeSwitchedUL_p->transportLayerAddress.size = 4;
//    e_RABToBeSwitchedUL_p->transportLayerAddress.bits_unused = 0;
//  }
//
//  // TODO: S1AP PDU..
//  /** Set the bearer as an ASN list element. */
////  S1AP_IE_t                               s1ap_ie_ext;
////  ssize_t                                 encoded;
////  S1AP_PDU_t                              pdu;
////
////  memset (&s1ap_ie_ext, 0, sizeof (S1AP_IE_t));
////  s1ap_ie_ext.id = S1AP_ProtocolIE_ID_id_Data_Forwarding_Not_Possible;
////  s1ap_ie_ext.criticality = S1AP_Criticality_ignore;
////  s1ap_ie_ext.value.buf = NULL;
////  s1ap_ie_ext.value.size = 0;
////  ASN_SEQUENCE_ADD (e_RABToBeSetupHO_p->iE_Extensions, &pdu);
//  /** Adding stacked value. */
//
//  if (bearer_ctx_p->s_gw_address.pdn_type == IPv6 ||bearer_ctx_p->s_gw_address.pdn_type == IPv4_AND_v6) {
//    if (bearer_ctx_p->s_gw_address.pdn_type == IPv6) {
//      /*
//       * Only IPv6 supported
//         */
//      /*
//       * TODO: check memory allocation
//       */
//      e_RABToBeSwitchedUL_p->transportLayerAddress.buf = calloc (16, sizeof (uint8_t));
//    } else {
//      /*
//       * Both IPv4 and IPv6 provided
//       */
//      /*
//       * TODO: check memory allocation
//       */
//      e_RABToBeSwitchedUL_p->transportLayerAddress.buf = realloc (e_RABToBeSwitchedUL_p->transportLayerAddress.buf, (16 + offset) * sizeof (uint8_t));
//    }
//
//    memcpy (&e_RABToBeSwitchedUL_p->transportLayerAddress.buf[offset], bearer_ctx_p->s_gw_address.address.ipv6_address, 16);
//    e_RABToBeSwitchedUL_p->transportLayerAddress.size = 16 + offset;
//    e_RABToBeSwitchedUL_p->transportLayerAddress.bits_unused = 0;
//  }
//
//  return RETURNok;
//}


//------------------------------------------------------------------------------
void
s1ap_handle_mme_ue_id_notification (
  const itti_mme_app_s1ap_mme_ue_id_notification_t * const notification_p)
{

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (notification_p != NULL);
  s1ap_notified_new_ue_mme_s1ap_id_association (
                          notification_p->sctp_assoc_id, notification_p->enb_ue_s1ap_id, notification_p->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
}
