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


/** @defgroup _s1ap_impl_ S1AP Layer Reference Implementation
 * @ingroup _ref_implementation_
 * @{
 */

#if HAVE_CONFIG_H_
# include "config.h"
#endif

#ifndef FILE_S1AP_COMMON_SEEN
#define FILE_S1AP_COMMON_SEEN

#include "bstrlib.h"

/* Defined in asn_internal.h */
// extern int asn_debug_indent;
extern int asn_debug;

#if defined(EMIT_ASN_DEBUG_EXTERN)
inline void ASN_DEBUG(const char *fmt, ...);
#endif

#include "S1AP_ProtocolIE-Field.h"
#include "S1AP_S1AP-PDU.h"
#include "S1AP_InitiatingMessage.h"
#include "S1AP_SuccessfulOutcome.h"
#include "S1AP_UnsuccessfulOutcome.h"
#include "S1AP_ProtocolIE-Field.h"
#include "S1AP_ProtocolIE-FieldPair.h"
#include "S1AP_ProtocolIE-ContainerPair.h"
#include "S1AP_ProtocolExtensionField.h"
#include "S1AP_ProtocolExtensionContainer.h"
#include "S1AP_asn_constant.h"
#include "S1AP_SupportedTAs-Item.h"
#include "S1AP_ServedGUMMEIsItem.h"


/* Checking version of ASN1C compiler */
#if (ASN1C_ENVIRONMENT_VERSION < ASN1C_MINIMUM_VERSION)
# error "You are compiling s1ap with the wrong version of ASN1C"
#endif

#define S1AP_FIND_PROTOCOLIE_BY_ID(IE_TYPE, ie, container, IE_ID, mandatory) \
  do {\
    IE_TYPE **ptr; \
    ie = NULL; \
    for (ptr = container->protocolIEs.list.array; \
         ptr < &container->protocolIEs.list.array[container->protocolIEs.list.count]; \
         ptr++) { \
      if((*ptr)->id == IE_ID) { \
        ie = *ptr; \
        break; \
      } \
    } \
    if (mandatory) DevAssert(ie != NULL); \
  } while(0)

extern int asn_debug;
extern int asn1_xer_print;

# include <stdbool.h>
# include "mme_default_values.h"
# include "3gpp_23.003.h"
# include "3gpp_24.008.h"
# include "3gpp_33.401.h"
# include "security_types.h"
# include "common_types.h"

//Forward declaration

/** \brief Function callback prototype.
 **/
typedef int (*s1ap_message_decoded_callback)(
    const sctp_assoc_id_t             assoc_id,
    const sctp_stream_id_t            stream,
    S1AP_S1AP_PDU_t                   *pdu
);

/** \brief Handle criticality
 \param criticality Criticality of the IE
 @returns void
 **/
void s1ap_handle_criticality(S1AP_Criticality_t criticality);

#endif /* FILE_S1AP_COMMON_SEEN */
