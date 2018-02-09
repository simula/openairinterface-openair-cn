#define SERVICE303
#define SERVICE303_TASK_C


#include "log.h"
#include "intertask_interface.h"
#include "timer.h"

#include "service303.h"


static long service303_epc_stats_timer_id;

static void service303_exit(void);

static void* service303_server_task (void* args)
{
  itti_mark_task_ready (TASK_SERVICE303_SERVER);
  service303_data_t* service303_data =  (service303_data_t*) args;

  // Blocking call to start server
  start_service303_server(service303_data->name,
                          service303_data->version);
  itti_exit_task ();
  return NULL;
}

static void* service303_message_task (void* args)
{
  itti_mark_task_ready (TASK_SERVICE303);
  service303_data_t* service303_data = (service303_data_t *) args;
  if (0 == bstricmp (service303_data->name, bfromcstr (SERVICE303_MME_PACKAGE_NAME))) {
    /* NOTE : Above check for MME package is added since SPGW does not support stats at present
     * TODO : Whenever SPGW implements stats,remove the above "if" check so that timer is started
     * in SPGW also and SPGW stats can also be read as part of timer expiry handling
     */

    /*
     * Check if this thread is started by MME service if so start a timer
     * to trigger reading the mme stats so that it cen be sent to server
     * for display
     * Start periodic timer
     */
    if (timer_setup (EPC_STATS_TIMER_VALUE, 0, TASK_SERVICE303, INSTANCE_DEFAULT, TIMER_PERIODIC, NULL, 0, &service303_epc_stats_timer_id) < 0) {
      OAILOG_ALERT (LOG_UTIL, " TASK SERVICE303_MESSAGE for EPC: Periodic Stat Timer Start: ERROR\n");
      service303_epc_stats_timer_id = 0;
    }
  }
  while (1) {
    MessageDef*                              received_message_p = NULL;
    /*
     * Trying to fetch a message from the message queue.
     * If the queue is empty, this function will block till a
     * message is sent to the task.
     */
    itti_receive_msg (TASK_SERVICE303, &received_message_p);

    switch (ITTI_MSG_ID (received_message_p)) {

    case TIMER_HAS_EXPIRED:{
      /*
       * Check statistic timer
       */
      if (!timer_exists (received_message_p->ittiMsg.timer_has_expired.timer_id)) {
        break;
      }
      if (received_message_p->ittiMsg.timer_has_expired.timer_id == service303_epc_stats_timer_id) {
        service303_statistics_read ();
      }
      timer_handle_expired(received_message_p->ittiMsg.timer_has_expired.timer_id);
      break;
    }
    case TERMINATE_MESSAGE:{
      timer_remove (service303_epc_stats_timer_id);
      service303_exit();
      itti_exit_task ();
      }
      break;
    case APPLICATION_HEALTHY_MSG:{
      service303_set_application_health(APP_HEALTHY);
      }
      break;
    case APPLICATION_UNHEALTHY_MSG:{
      service303_set_application_health(APP_UNHEALTHY);
      }
      break;
    default:{
        OAILOG_DEBUG (LOG_UTIL, "Unkwnon message ID %d: %s\n", ITTI_MSG_ID (received_message_p), ITTI_MSG_NAME (received_message_p));
      }
      break;
    }
    itti_free (ITTI_MSG_ORIGIN_ID (received_message_p), received_message_p);
    received_message_p = NULL;
  }
  return NULL;
}


int service303_init (service303_data_t* service303_data)
{
  OAILOG_DEBUG (LOG_UTIL, "Initializing Service303 task interface\n");

  if (itti_create_task (TASK_SERVICE303_SERVER, &service303_server_task, service303_data) < 0) {
    perror ("pthread_create");
    OAILOG_ALERT (LOG_UTIL, "Initializing Service303 server: ERROR\n");
    return RETURNerror;
  }

  if (itti_create_task (TASK_SERVICE303, &service303_message_task, service303_data) < 0) {
    perror ("pthread_create");
    OAILOG_ALERT (LOG_UTIL, "Initializing Service303 message interface: ERROR\n");
    return RETURNerror;
  }

  OAILOG_DEBUG (LOG_UTIL, "Initializing Service303 task interface: DONE\n");
  return RETURNok;
}

static void service303_exit(void)
{
  stop_service303_server();
}
