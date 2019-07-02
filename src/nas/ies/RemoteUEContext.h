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
 * Unless required by applicable law or agreed to in writing, softwarek
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef REMOTE_UE_CONTEXT
#define REMOTE_UE_CONTEXT
#include "RemoteUserID.h"


#define REMOTE_UE_CONTEXT_MINIMUM_LENGTH 16
#define REMOTE_UE_CONTEXT_MAXIMUM_LENGTH 28


typedef struct remote_ue_context_s {
		uint8_t  spare:4;
//#define REMOTE_UE_MOBILE_IDENTITY_IMSI  010
		//uint8_t typeofuseridentity:3;
#define NUMBER_OF_REMOTE_UE_CONTEXT_IDENTITIES 1
		uint8_t numberofuseridentity:8;
#define EVEN_IDENTITY 0
#define ODD_IDENTITY  1
		uint8_t oddevenindic:1;
		bool     flags_present;
		imsi_identity_t *imsi_identity
}remote_ue_context_t;

/*typedef struct imsi_identity_s {
  uint8_t  identity_digit1:4;
#define IMSI_EVEN  0
#define IMSI_ODD   1
  uint8_t  oddeven:1;
#define REMOTE_UE_MOBILE_IDENTITY_IMSI  010
  uint8_t  typeofidentity:3;
  uint8_t  identity_digit2:4;
  uint8_t  identity_digit3:4;
  uint8_t  identity_digit4:4;
  uint8_t  identity_digit5:4;
  uint8_t  identity_digit6:4;
  uint8_t  identity_digit7:4;
  uint8_t  identity_digit8:4;
  uint8_t  identity_digit9:4;
  uint8_t  identity_digit10:4;
  uint8_t  identity_digit11:4;
  uint8_t  identity_digit12:4;
  uint8_t  identity_digit13:4;
  uint8_t  identity_digit14:4;
  uint8_t  identity_digit15:4;
  // because of union put this extra attribute at the end
  uint8_t  num_digits;
} imsi_identity_t;*/


//typedef union remote_ue_mobile_identity_s {
//#define REMOTE_UE_MOBILE_IDENTITY_IMSI_ENCRYPTED  001
//#define REMOTE_UE_MOBILE_IDENTITY_IMSI  010
//#define REMOTE_UE_MOBILE_IDENTITY_MSISDN  011
//#define REMOTE_UE_MOBILE_IDENTITY_IMEI  100
//#define REMOTE_UE_MOBILE_IDENTITY_IMEISV  101
//	imsi_e_remote_ue_mobile_identity_t imsi_encrypted;
//	imsi_remote_ue_mobile_identity_t imsi;
//	msisdn_remote_ue_mobile_identity_t msisdn;
//	imei_remote_ue_mobile_identity_t imei;
//	imeisv_remote_ue_mobile_identity_t imeisv;
//} remote_ue_mobile_identity_t;
//#define REMOTE_UE_MOBILE_IDENTITY    "remote_ue_identity_type"

  int encode_remote_ue_context(remote_ue_context_t *remoteuecontext, uint8_t iei, uint8_t *buffer, uint32_t len);

  int decode_remote_ue_context(remote_ue_context_t *remoteuecontext, uint8_t iei, uint8_t *buffer, uint32_t len);

  #endif
