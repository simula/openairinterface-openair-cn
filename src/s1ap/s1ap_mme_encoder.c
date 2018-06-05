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


/*! \file s1ap_mme_encoder.c
   \brief s1ap encode procedures for MME
   \author Sebastien ROUX <sebastien.roux@eurecom.fr>
   \date 2012
   \version 0.1
*/
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>

#include "bstrlib.h"

#include "intertask_interface.h"
#include "mme_api.h"
#include "s1ap_common.h"
#include "s1ap_mme_encoder.h"
#include "assertions.h"
#include "log.h"

int
s1ap_mme_encode_pdu (
  S1AP_S1AP_PDU_t * pdu,
  uint8_t ** buffer,
  uint32_t * length)
{
  asn_encode_to_new_buffer_result_t res = { NULL, {0, NULL, NULL} };

  DevAssert (pdu != NULL);
  DevAssert (buffer != NULL);
  DevAssert (length != NULL);

  res = asn_encode_to_new_buffer(NULL, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_S1AP_S1AP_PDU, pdu);
  if (res.result.encoded > 0) {
    *buffer = res.buffer;
    *length = res.result.encoded;
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_S1AP_PDU, pdu);
    return 0;
  }

  return -1;
}

