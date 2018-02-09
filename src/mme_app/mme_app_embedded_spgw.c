#include <unistd.h>

#include "mme_app_embedded_spgw.h"
#include "common_defs.h"

static void usage (char *target)
{
  OAILOG_INFO (LOG_CONFIG, "==== EURECOM %s version: %s ====\n", PACKAGE_NAME, PACKAGE_VERSION);
  OAILOG_INFO (LOG_CONFIG, "Please report any bug to: %s\n", PACKAGE_BUGREPORT);
  OAILOG_INFO (LOG_CONFIG, "Usage: %s [options]\n", target);
  OAILOG_INFO (LOG_CONFIG, "Available options:\n");
  OAILOG_INFO (LOG_CONFIG, "-h      Print this help and return\n");
  OAILOG_INFO (LOG_CONFIG, "-c <path>\n");
  OAILOG_INFO (LOG_CONFIG, "        Set the configuration file for mme\n");
  OAILOG_INFO (LOG_CONFIG, "        See template in UTILS/CONF\n");
  OAILOG_INFO (LOG_CONFIG, "-s <path>\n");
  OAILOG_INFO (LOG_CONFIG, "        Set the configuration file for S/P-GW\n");
  OAILOG_INFO (LOG_CONFIG, "        See template in ETC\n");
  OAILOG_INFO (LOG_CONFIG, "-K <file>\n");
  OAILOG_INFO (LOG_CONFIG, "        Output intertask messages to provided file\n");
  OAILOG_INFO (LOG_CONFIG, "-V      Print %s version and return\n", PACKAGE_NAME);
  OAILOG_INFO (LOG_CONFIG, "-v[1-2] Debug level:\n");
  OAILOG_INFO (LOG_CONFIG, "            1 -> ASN1 XER printf on and ASN1 debug off\n");
  OAILOG_INFO (LOG_CONFIG, "            2 -> ASN1 XER printf on and ASN1 debug on\n");
}

int
mme_config_embedded_spgw_parse_opt_line (
  int argc,
  char *argv[],
  mme_config_t * mme_config_p,
  spgw_config_t * spgw_config_p)
{
  int c;

  mme_config_init (mme_config_p);
  spgw_config_init (spgw_config_p);

  /*
   * Parsing command line
   */
  while ((c = getopt (argc, argv, "c:hi:Ks:v:V")) != -1) {
    switch (c) {
    case 'c':{
        /*
         * Store the given configuration file. If no file is given,
         * * * * then the default values will be used.
         */
        mme_config_p->config_file = blk2bstr(optarg, strlen(optarg));
        OAILOG_DEBUG (LOG_CONFIG, "%s mme_config.config_file %s\n", __FUNCTION__, bdata(mme_config_p->config_file));
      }
      break;

    case 'v':{
        mme_config_p->log_config.asn1_verbosity_level = atoi (optarg);
      }
      break;

    case 'V':{
        OAILOG_DEBUG (LOG_CONFIG, "==== EURECOM %s v%s ====" "Please report any bug to: %s\n", PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_BUGREPORT);
      }
      break;

    case 'K':{
        mme_config_p->itti_config.log_file = blk2bstr (optarg, strlen(optarg));
        OAILOG_DEBUG (LOG_CONFIG, "%s mme_config.itti_config.log_file %s\n", __FUNCTION__, bdata(mme_config_p->itti_config.log_file));
        spgw_config_p->sgw_config.itti_config.log_file = blk2bstr (optarg, strlen(optarg));
        OAILOG_DEBUG (LOG_CONFIG, "spgw_config.sgw_config.itti_config.log_file %s\n", bdata(spgw_config_p->sgw_config.itti_config.log_file));
      }
      break;

    case 's':{
        /*
         * Store the given configuration file. If no file is given,
         * * * * then the default values will be used.
         */
        spgw_config_p->config_file = blk2bstr(optarg, strlen(optarg));
        spgw_config_p->pgw_config.config_file = bstrcpy(spgw_config_p->config_file);
        spgw_config_p->sgw_config.config_file = bstrcpy(spgw_config_p->config_file);
        OAILOG_DEBUG (LOG_CONFIG, "spgw_config.config_file %s\n", bdata(spgw_config_p->config_file));
      }
      break;

    case 'h':                  /* Fall through */
    default:
      usage (argv[0]);
      exit (0);
    }
  }

  /*
   * Parse the configuration files using libconfig
   */
  if (!mme_config_p->config_file) {
    mme_config_p->config_file = bfromcstr("/usr/local/etc/oai/mme.conf");
  }
  if (mme_config_parse_file (mme_config_p) != 0) {
    return -1;
  }

  if (!spgw_config_p->config_file) {
    spgw_config_p->config_file            = bfromcstr("/usr/local/etc/oai/spgw.conf");
    spgw_config_p->pgw_config.config_file = bfromcstr("/usr/local/etc/oai/spgw.conf");
    spgw_config_p->sgw_config.config_file = bfromcstr("/usr/local/etc/oai/spgw.conf");
  }
  if (spgw_config_parse_file (spgw_config_p) != 0) {
    return RETURNerror;
  }

  /*
   * Display the configuration
   */
  mme_config_display (mme_config_p);
  spgw_config_display (spgw_config_p);
  return RETURNok;
}
