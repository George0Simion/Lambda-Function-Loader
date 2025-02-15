// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../src/ipc.h"

#define USERNAME_MAX_LEN 32
#define PATH_MAX_LEN 128

int is_valid_username(const char *username) {
    if (strlen(username) == 0 || strlen(username) > USERNAME_MAX_LEN) {
        return 0;
    }
    for (size_t i = 0; i < strlen(username); i++) {
        if (!isalnum(username[i]) && username[i] != '_') {
            return 0; // Only allow alphanumeric and underscore
        }
    }
    return 1;
}
int create_account(int fd) {
    char username[USERNAME_MAX_LEN];
    char password[256];
    char buf[BUFSIZE];
    int ret;

    while (1) {
        // Prompt for the username
        printf("Enter a new username (or type 'cancel' to exit): ");
        if (!fgets(username, sizeof(username), stdin)) {
            fprintf(stderr, "Error reading username\n");
            return -1;
        }

        // Remove newline character if present
        username[strcspn(username, "\n")] = '\0';

        // Check if the user wants to cancel the operation
        if (strcmp(username, "cancel") == 0) {
            printf("Account creation canceled.\n");
            return -1;
        }

        // Validate username
        if (!is_valid_username(username)) {
            fprintf(stderr, "Invalid username. Use only alphanumeric characters and underscores.\n");
            continue; // Prompt for username again
        }

        // If username is valid, break out of the loop
        break;
    }

    // Prompt for the password
    printf("Enter a new password: ");
    if (!fgets(password, sizeof(password), stdin)) {
        fprintf(stderr, "Error reading password\n");
        return -1;
    }

    // Remove newline character if present
    password[strcspn(password, "\n")] = '\0';

    // Send the create account command to the server
    snprintf(buf, BUFSIZE, "CREATE_ACCOUNT %s %s", username, password);
    ret = send_socket(fd, buf, strlen(buf));
    if (ret < 0) {
        fprintf(stderr, "Failed to send create account command\n");
        return -1;
    }

    // Wait for the server's response
    memset(buf, 0, BUFSIZE);
    ret = recv_socket(fd, buf, BUFSIZE);
    if (ret < 0) {
        fprintf(stderr, "Failed to receive create account response\n");
        return -1;
    }

    // Check the server's response
    if (strncmp(buf, "SUCCESS", 7) == 0) {
        printf("Account creation successful. You can now log in.\n");
        return 0;
    } else {
        printf("Account creation failed: %s\n", buf);
        return -1;
    }
}

int login(int fd) {
    char username[USERNAME_MAX_LEN];
    char password[256];
    char buf[BUFSIZE];
    int ret;

    // Prompt for the username
    printf("Enter username (or press Enter to create a new account): ");
    if (!fgets(username, sizeof(username), stdin)) {
        fprintf(stderr, "Error reading username\n");
        return -1;
    }

    // Remove newline character if present
    username[strcspn(username, "\n")] = '\0';

    // If username is empty, trigger account creation
    if (strlen(username) == 0) {
        return create_account(fd);
    }

    // Validate username
    if (!is_valid_username(username)) {
        fprintf(stderr, "Invalid username. Use only alphanumeric characters and underscores.\n");
        return -1;
    }

    // Prompt for the password
    printf("Enter password: ");
    if (!fgets(password, sizeof(password), stdin)) {
        fprintf(stderr, "Error reading password\n");
        return -1;
    }

    // Remove newline character if present
    password[strcspn(password, "\n")] = '\0';

    // Send the login command to the server
    snprintf(buf, BUFSIZE, "LOGIN %s %s", username, password);
    ret = send_socket(fd, buf, strlen(buf));
    if (ret < 0) {
        fprintf(stderr, "Failed to send login command\n");
        return -1;
    }

    // Wait for the server's response
    memset(buf, 0, BUFSIZE);
    ret = recv_socket(fd, buf, BUFSIZE);
    if (ret < 0) {
        fprintf(stderr, "Failed to receive login response\n");
        return -1;
    }

    // Check the server's response
    if (strncmp(buf, "SUCCESS", 7) == 0) {
        printf("Login successful.\n");
        return 0;
    } else {
        printf("Login failed: %s\n", buf);
        return -1;
    }
}

int main(int argc, char *argv[]) {
    int fd = -1;
    int ret = -1;

    /* Buffer for the command to be sent to the server. */
    char buf[BUFSIZE];

    memset(buf, 0, BUFSIZE);

    /* Create the socket to be used for communication with the server. */
    fd = create_socket();
    if (fd == -1) {
        perror("unix socket");
        exit(-1);
    }

    /* Connect to the socket used to communicate with the server. */
    ret = connect_socket(fd);
    if (ret == -1) {
        perror("connect unix socket");
        exit(-1);
    }

    /* Perform login */
    if (login(fd) < 0) {
        fprintf(stderr, "Authentication failed. Exiting.\n");
        close_socket(fd);
        exit(-1);
    }

    /* Format command based on program arguments. */
    switch (argc) {
    case 2:
        snprintf(buf, BUFSIZE, "%s", argv[1]);
        break;
    case 3:
        snprintf(buf, BUFSIZE, "%s %s", argv[1], argv[2]);
        break;
    case 4:
        snprintf(buf, BUFSIZE, "%s %s %s", argv[1], argv[2], argv[3]);
        break;
    default:
        fprintf(stderr, "Illegal client format\n");
        close_socket(fd);
        exit(-1);
    }

    /* Send the command to the server. */
    send_socket(fd, buf, strlen(buf));

    /* Wait for the response from the server. */
    memset(buf, 0, BUFSIZE);
    ret = recv_socket(fd, buf, BUFSIZE);
    if (ret < 0) {
        perror("recv_socket failed");
        close_socket(fd);
        exit(-1);
    }
    buf[BUFSIZE - 1] = '\0';

    /* Print the result. */
    printf("Output file: %s\n", buf);

    /* Close connection with the server. */
    close_socket(fd);

    return 0;
}