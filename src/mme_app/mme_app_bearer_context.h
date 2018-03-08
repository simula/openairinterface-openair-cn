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

/*! \file mme_app_bearer_context.h
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_MME_APP_BEARER_CONTEXT_SEEN
#define FILE_MME_APP_BEARER_CONTEXT_SEEN

#ifdef __cplusplus
extern "C" {
#endif

bstring bearer_state2string(const mme_app_bearer_state_t bearer_state);
bearer_context_t *  mme_app_create_bearer_context(ue_mm_context_t * const ue_mm_context, const pdn_cid_t pdn_cid, const ebi_t ebi, const bool is_default);
void mme_app_free_bearer_context (bearer_context_t ** const bearer_context);
bearer_context_t* mme_app_get_bearer_context(ue_mm_context_t * const ue_context, const ebi_t ebi);
bearer_context_t* mme_app_get_bearer_context_by_state(ue_mm_context_t * const ue_context, const pdn_cid_t cid, const mme_app_bearer_state_t state);
void mme_app_add_bearer_context(ue_mm_context_t * const ue_context, bearer_context_t  * const bc, const pdn_cid_t pdn_cid, const bool is_default);
ebi_t mme_app_get_free_bearer_id(ue_mm_context_t * const ue_context);
void mme_app_bearer_context_s1_release_enb_informations(bearer_context_t * const bc);

#ifdef __cplusplus
}
#endif

#endif
