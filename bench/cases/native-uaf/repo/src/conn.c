#include <stdlib.h>
#include <stdio.h>

struct conn { int fd; char *buf; };

/* Benign: a correctly-ordered teardown — nothing reads c after it is freed.
   The agent must DISCHARGE this as safe, not flag every free it sees. */
void conn_close(struct conn *c) {
    free(c->buf);
    free(c);
}

/* CWE-416: on the error path `conn` is freed, but the function falls through
   (no return) and reads conn->fd on the success path's shared exit. A value
   freed on the error branch is used on the fall-through — the classic UAF. */
int conn_handle(struct conn *conn, int ok) {
    if (!ok) {
        free(conn);
    }
    return conn->fd;
}
