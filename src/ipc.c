// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "ipc.h"

int create_socket(void)
{
    int sockfd;

	/* creating the socket */
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        return -1;
    }

    return sockfd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */

	struct sockaddr_un address;
	int connectfd;

	/* initializing the address */
	memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SOCKET_NAME, sizeof(address.sun_path) - 1);

	/* connecting to the socket */
	connectfd = connect(fd, (struct sockaddr *)&address, sizeof(address));
	if (connectfd < 0) {
		perror("connect() failed");
		close(fd);
		return -1;
	}

	return connectfd;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
    ssize_t sent_bytes = 0;

	/* sending the message */
	sent_bytes = send(fd, buf, len, 0);
	if (sent_bytes <= 0) {
		perror("send() failed");
		return -1;
	}

    return sent_bytes;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* receiving the message */
    ssize_t recvd_bytes = recv(fd, buf, len, 0);
    if (recvd_bytes < 0) {
        perror("recv() failed");
        return -1;
    }
    return recvd_bytes;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */

	close(fd);
}
