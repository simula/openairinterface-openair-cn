#define SERVICE303

#include "mme_app_defs.h"

static void service303_mme_statistics_read (void)
{
  size_t label = 0;
  set_gauge ("enb_connected", mme_app_desc.nb_enb_connected, label);
  set_gauge ("ue_registered", mme_app_desc.nb_ue_attached, label);
  set_gauge ("ue_connected", mme_app_desc.nb_ue_connected, label);
  return;
}

void service303_statistics_read (void)
{
  service303_mme_statistics_read ();
  return;
}
