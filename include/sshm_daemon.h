#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#define DAEMON_SOCKET "/tmp/sshm_daemon.sock"

/* Start the daemon (blocking) */
int sshm_run_daemon(void);

/* Cleanup resources (socket, memory) */
void sshm_daemon_cleanup(void);

#ifdef __cplusplus
}
#endif


