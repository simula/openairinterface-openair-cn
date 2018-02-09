/**
 * Copyright (c) 2017-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

#include <netinet/in.h>

#include "log.h"
#include "pgw_ue_ip_address_alloc.h"
#include "service303.h"

int allocate_ue_ipv4_address(const char *imsi, struct in_addr *addr) {
  // Call PGW IP Address allocator 
  int ip_alloc_status = RPC_STATUS_OK; 
  ip_alloc_status = allocate_ipv4_address (imsi, addr);
  if (ip_alloc_status == RPC_STATUS_ALREADY_EXISTS) {
    increment_counter ("ue_pdn_connection", 1, 2, "pdn_type", "ipv4", "result", "ip_address_already_allocated");
    /*
     * This implies that UE session was not release properly.
     * Release the IP address so that subsequent attempt is successfull
     */
    release_ipv4_address (imsi, addr);
    // TODO - Release the GTP-tunnel corresponding to this IP address
  }

  if (ip_alloc_status != RPC_STATUS_OK) {
    OAILOG_ERROR (LOG_SPGW_APP, "Failed to allocate IPv4 PAA for PDN type IPv4. IP alloc status = %d \n", ip_alloc_status);
  }
  return ip_alloc_status;
}

int release_ue_ipv4_address(const char *imsi, struct in_addr *addr) {
    increment_counter ("ue_pdn_connection", 1, 2, "pdn_type", "ipv4", "result", "ip_address_released");
  // Release IP address back to PGW IP Address allocator 
  return release_ipv4_address (imsi, addr); 
}

void pgw_ip_address_pool_init (void) {
  return;
}

int get_ip_block(struct in_addr *netaddr, uint32_t *netmask) {
  int rv;

  rv = get_assigned_ipv4_block(0, netaddr, netmask);
  if (rv != 0) {
    OAILOG_CRITICAL (LOG_GTPV1U, "ERROR in getting assigned IP block from mobilityd\n");
    return -1;
  }
  return rv;
}

