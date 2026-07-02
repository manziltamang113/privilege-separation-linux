#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SOCKET_PATH "/tmp/auth.sock"
#define BUF_SIZE 256

int main(void) {
    printf("[backend] starting. Effective UID = %d (should be 0 = root)\n", geteuid());

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(SOCKET_PATH);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); exit(1); }

    if (chmod(SOCKET_PATH, 0666) < 0) { perror("chmod"); exit(1); }

    if (listen(listen_fd, 1) < 0) { perror("listen"); exit(1); }

    printf("[backend] listening on %s\n", SOCKET_PATH);

    int conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) { perror("accept"); exit(1); }
    printf("[backend] frontend connected.\n");

    close(conn_fd);
    close(listen_fd);
    unlink(SOCKET_PATH);

    return 0;
}
