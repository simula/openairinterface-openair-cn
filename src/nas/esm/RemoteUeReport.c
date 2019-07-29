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

/*****************************************************************************
  Source      RemoteUeReport.c

  Version     0.1

  Date        2019/09/18

  Product     NAS stack

  Subsystem   EPS Session Management

  Author      Mohit Vyas

  Description Defines the Remote UE Report ESM procedure executed by the
        UE on Non-Access Stratum.

        The Remote UE Report procedure is used by the UE to inform the network about a new remote UE which is connected/disconnected.


*****************************************************************************/
#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "bstrlib.h"

#include "dynamic_memory_check.h"
#include "assertions.h"
#include "log.h"
#include "common_types.h"
#include "3gpp_24.007.h"
#include "3gpp_24.008.h"
#include "3gpp_29.274.h"
#include "3gpp_36.401.h"
#include "mme_app_ue_context.h"
#include "commonDef.h"
#include "esm_proc.h"
#include "esm_data.h"
#include "esm_ebr.h"
#include "esm_cause.h"
#include "esm_pt.h"
#include "mme_api.h"
#include "emm_sap.h"
#include "mme_app_apn_selection.h"
#include "mme_app_pdn_context.h"
#include "mme_app_bearer_context.h"
#include "mme_app_defs.h"


int esm_proc_remote_ue_report (proc_tid_t pti, esm_cause_t *esm_cause, emm_data_context_t * emm_context, ebi_t ebi)
{
	OAILOG_FUNC_IN (LOG_NAS_ESM);
	  pdn_cid_t                               pid = RETURNerror;
	  mme_ue_s1ap_id_t                        ue_id = emm_context->ue_id;
	  pdn_context_t                          *pdn_context = NULL;



}

