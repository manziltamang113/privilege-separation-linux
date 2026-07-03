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

    char buf[BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    ssize_t n = read(conn_fd, buf, sizeof(buf) - 1);
    if (n <= 0) { perror("read"); close(conn_fd); exit(1); }
    buf[n] = '\0';

    printf("[backend] received credential request (length %zd bytes)\n", n);

    char *colon = strchr(buf, ':');
    if (!colon) {
        write(conn_fd, "FAIL", 4);
        close(conn_fd);
        exit(1);
    }
    *colon = '\0';
    char *username = buf;
    char *password = colon + 1;

    printf("[backend] checking credentials for user '%s' (still root, euid=%d)\n",
           username, geteuid());

    FILE *fp = fopen("secrets.txt", "r");
    if (!fp) {
        perror("fopen secrets.txt");
        write(conn_fd, "FAIL", 4);
        close(conn_fd);
        exit(1);
    }

    int authenticated = 0;
    char line[BUF_SIZE];

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';

        char *file_colon = strchr(line, ':');
        if (!file_colon) continue;
        *file_colon = '\0';
        char *file_user = line;
        char *file_pass = file_colon + 1;

        if (strcmp(username, file_user) == 0 && strcmp(password, file_pass) == 0) {
            authenticated = 1;
            break;
        }
    }
    fclose(fp);

    printf("[backend] authentication result: %s\n", authenticated ? "SUCCESS" : "FAILURE");

    explicit_bzero(buf, sizeof(buf));

    if (authenticated) {
        write(conn_fd, "OK", 2);
    } else {
        write(conn_fd, "FAIL", 4);
    }

    close(conn_fd);
    close(listen_fd);
    unlink(SOCKET_PATH);

    return 0;
}
