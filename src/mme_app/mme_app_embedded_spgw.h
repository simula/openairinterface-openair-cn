#ifndef FILE_MME_APP_SPGW_SEEN
#define FILE_MME_APP_SPGW_SEEN
#include "mme_config.h"
#include "spgw_config.h"
#include "sgw_defs.h"

int
mme_config_embedded_spgw_parse_opt_line (
  int argc,
  char *argv[],
  mme_config_t *,
  spgw_config_t *);

#endif /* ifndef FILE_MME_APP_SPGW_SEEN */
