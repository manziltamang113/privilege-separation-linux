#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK "/tmp/auth.sock"
#define BUF 256

int main(void) {
    printf("[frontend] uid=%d\n", getuid());

    char user[64], pass[64];
    printf("Username: "); fgets(user, 64, stdin); user[strcspn(user,"\n")]='\0';
    printf("Password: "); fgets(pass, 64, stdin); pass[strcspn(pass,"\n")]='\0';

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, SOCK, sizeof(addr.sun_path)-1);
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));

    char msg[BUF];
    snprintf(msg, BUF, "%s:%s", user, pass);
    write(fd, msg, strlen(msg));
    explicit_bzero(msg, BUF);
    explicit_bzero(pass, 64);

    char reply[8] = {0};
    read(fd, reply, 7);
    close(fd);

    printf("[frontend] %s\n", strcmp(reply,"OK")==0 ? "Authentication SUCCESSFUL" : "Authentication FAILED");
    return 0;
}
