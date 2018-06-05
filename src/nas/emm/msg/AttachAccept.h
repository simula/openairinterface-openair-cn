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


#ifndef FILE_ATTACH_ACCEPT_SEEN
#define FILE_ATTACH_ACCEPT_SEEN

#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "EpsAttachResult.h"
#include "TrackingAreaIdentityList.h"
#include "EsmMessageContainer.h"
#include "EpsMobileIdentity.h"
#include "EmmCause.h"
#include "EpsNetworkFeatureSupport.h"
#include "AdditionalUpdateResult.h"
#include "3gpp_23.003.h"
#include "3gpp_24.007.h"
#include "3gpp_24.008.h"

/* Minimum length macro. Formed by minimum length of each mandatory field */
#define ATTACH_ACCEPT_MINIMUM_LENGTH ( \
    EPS_ATTACH_RESULT_MINIMUM_LENGTH + \
    GPRS_TIMER_IE_MIN_LENGTH + \
    TRACKING_AREA_IDENTITY_LIST_MINIMUM_LENGTH + \
    ESM_MESSAGE_CONTAINER_MINIMUM_LENGTH )

/* Maximum length macro. Formed by maximum length of each field */
#define ATTACH_ACCEPT_MAXIMUM_LENGTH ( \
    EPS_ATTACH_RESULT_MAXIMUM_LENGTH + \
    GPRS_TIMER_IE_MAX_LENGTH + \
    TRACKING_AREA_IDENTITY_LIST_MAXIMUM_LENGTH + \
    ESM_MESSAGE_CONTAINER_MAXIMUM_LENGTH + \
    EPS_MOBILE_IDENTITY_MAXIMUM_LENGTH + \
    LOCATION_AREA_IDENTIFICATION_MAXIMUM_LENGTH + \
    MOBILE_IDENTITY_MAXIMUM_LENGTH + \
    EMM_CAUSE_MAXIMUM_LENGTH + \
    GPRS_TIMER_MAXIMUM_LENGTH + \
    GPRS_TIMER_MAXIMUM_LENGTH + \
    PLMN_LIST_MAXIMUM_LENGTH + \
    EMERGENCY_NUMBER_LIST_MAXIMUM_LENGTH + \
    EPS_NETWORK_FEATURE_SUPPORT_MAXIMUM_LENGTH + \
    ADDITIONAL_UPDATE_RESULT_MAXIMUM_LENGTH )

/* If an optional value is present and should be encoded, the corresponding
 * Bit mask should be set to 1.
 */
# define ATTACH_ACCEPT_GUTI_PRESENT                         (1<<0)
# define ATTACH_ACCEPT_LOCATION_AREA_IDENTIFICATION_PRESENT (1<<1)
# define ATTACH_ACCEPT_MS_IDENTITY_PRESENT                  (1<<2)
# define ATTACH_ACCEPT_EMM_CAUSE_PRESENT                    (1<<3)
# define ATTACH_ACCEPT_T3402_VALUE_PRESENT                  (1<<4)
# define ATTACH_ACCEPT_T3423_VALUE_PRESENT                  (1<<5)
# define ATTACH_ACCEPT_EQUIVALENT_PLMNS_PRESENT             (1<<6)
# define ATTACH_ACCEPT_EMERGENCY_NUMBER_LIST_PRESENT        (1<<7)
# define ATTACH_ACCEPT_EPS_NETWORK_FEATURE_SUPPORT_PRESENT  (1<<8)
# define ATTACH_ACCEPT_ADDITIONAL_UPDATE_RESULT_PRESENT     (1<<9)

typedef enum attach_accept_iei_tag {
  ATTACH_ACCEPT_GUTI_IEI                          = 0x50, /* 0x50 = 80 */
  ATTACH_ACCEPT_LOCATION_AREA_IDENTIFICATION_IEI  = C_LOCATION_AREA_IDENTIFICATION_IEI,
  ATTACH_ACCEPT_MS_IDENTITY_IEI                   = C_MOBILE_IDENTITY_IEI,
  ATTACH_ACCEPT_EMM_CAUSE_IEI                     = 0x53, /* 0x53 = 83 */
  ATTACH_ACCEPT_T3402_VALUE_IEI                   = GPRS_C_TIMER_3402_VALUE_IEI,
  ATTACH_ACCEPT_T3423_VALUE_IEI                   = GPRS_C_TIMER_3423_VALUE_IEI,
  ATTACH_ACCEPT_EQUIVALENT_PLMNS_IEI              = C_PLMN_LIST_IEI,
  ATTACH_ACCEPT_EMERGENCY_NUMBER_LIST_IEI         = MM_EMERGENCY_NUMBER_LIST_IEI,
  ATTACH_ACCEPT_EPS_NETWORK_FEATURE_SUPPORT_IEI   = 0x64, /* 0x64 = 100 */
  ATTACH_ACCEPT_ADDITIONAL_UPDATE_RESULT_IEI      = 0xF0, /* 0xF0 = 240 */

// release 10.15.0
  ATTACH_ACCEPT_T3412_EXTENDED_VALUE_IEI          = 0x5E, /* 0x5E =     */
// release 12.13.0
  ATTACH_ACCEPT_T3324_VALUE_IEI                   = 0x6A, /* 0x6A =     */
// release 14.7.0
  ATTACH_ACCEPT_EXTENDED_DRX_PARAMETERS_IEI       = 0x6E, /* 0x6E =     */
  ATTACH_ACCEPT_DCN_ID_IEI                        = 0x65, /* 0x65 =     */
  ATTACH_ACCEPT_SMS_SERVICES_STATUS_IEI           = 0xE0, /* 0xE0 =     */
  ATTACH_ACCEPT_NON_3GPP_NW_PROVIDED_POLICIES_IEI = 0xD0, /* 0xD0 =     */
  ATTACH_ACCEPT_T3448_VALUE_IEI                   = 0x6E, /* 0x6B =     */
  ATTACH_ACCEPT_NETWORK_POLICIES_IEI              = 0xC0, /* 0xC0 =     */
// release 15.2.0
  ATTACH_ACCEPT_T3447_VALUE_IEI                   = 0x6C, /* 0x6C =     */
  ATTACH_ACCEPT_EXTENDED_EMERGENCY_NUMBER_LIST_IEI = 0x35, /* 0x35 =    */
} attach_accept_iei;

/*
 * Message name: Attach accept
 * Description: This message is sent by the network to the UE to indicate that the corresponding attach request has been accepted. See table 8.2.1.1.
 * Significance: dual
 * Direction: network to UE
 */

typedef struct attach_accept_msg_tag {
  /* Mandatory fields */
  eps_protocol_discriminator_t    protocoldiscriminator:4;
  security_header_type_t          securityheadertype:4;
  message_type_t                  messagetype;
  eps_attach_result_t             epsattachresult;
  gprs_timer_t                    t3412value;
  tai_list_t                      tailist;
  EsmMessageContainer             esmmessagecontainer;
  /* Optional fields */
  uint32_t                        presencemask;
  eps_mobile_identity_t           guti;
  location_area_identification_t  locationareaidentification;
  mobile_identity_t               msidentity;
  emm_cause_t                     emmcause;
  gprs_timer_t                    t3402value;
  gprs_timer_t                    t3423value;
  plmn_list_t                     equivalentplmns;
  emergency_number_list_t         emergencynumberlist;
  eps_network_feature_support_t   epsnetworkfeaturesupport;
  additional_update_result_t      additionalupdateresult;
} attach_accept_msg;

int decode_attach_accept(attach_accept_msg *attachaccept, uint8_t *buffer, uint32_t len);

int encode_attach_accept(attach_accept_msg *attachaccept, uint8_t *buffer, uint32_t len);

#endif /* ! defined(FILE_ATTACH_ACCEPT_SEEN) */

