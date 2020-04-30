#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

const char *USAGE = "demoapp <dst_ip4>\n";

/* Connect via TCP to destination, send a hello message and shutdown. */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Wrong number of arguments\n");
        printf("%s", USAGE);
        return EXIT_FAILURE;
    }

    int sockfd = -1;
    const char *ip_addr = argv[1];
    const short port = 8391;

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_aton(ip_addr, &dst.sin_addr) == 0) {
        fprintf(stderr, "Invalid IP address\n");
        return EXIT_FAILURE;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to open socket\n");
        return EXIT_FAILURE;
    }

    printf("Trying to connect to: %s\n", inet_ntoa(dst.sin_addr));
    fflush(stdout);

    if (connect(sockfd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        fprintf(stderr, "Failed to connect to destination %s:%d/tcp\n", ip_addr, port);
        close(sockfd);
        return EXIT_FAILURE;
    }

    const char *msg = "Hello world!\n";
    int ret = send(sockfd, (void *)msg, strlen(msg)+1, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to send message to destination\n");
        close(sockfd);
        return EXIT_FAILURE;
    }

    if (ret != (strlen(msg)+1)) printf("Less than full message send: %d instead of %lu\n", ret, strlen(msg)+1);
    else printf("Successfully sent message!\n");

    close(sockfd);
    return EXIT_SUCCESS;
}