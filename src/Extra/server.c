	// SPDX-License-Identifier: BSD-3-Clause

	#include <dlfcn.h>
	#include <fcntl.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <sys/stat.h>
	#include <sys/types.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/un.h>
	#include <sys/wait.h>
	#include <sys/resource.h>
	#include <signal.h>

	#include "ipc.h"
	#include "server.h"

	#ifndef OUTPUT_TEMPLATE
	#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
	#endif

	#include <ctype.h>
	#include <errno.h>
	#include <sys/stat.h>

	#define USER_BASE_DIR "/user"
	#define USERNAME_MAX_LEN 32
	#define PATH_MAX_LEN 128

	//* Hashing function */
	void custom_hash(const char *input, char *output, size_t output_size) {
		unsigned char hash = 0;
		size_t len = strlen(input);
		for (size_t i = 0; i < len; i++) {
			hash = (hash * 31) ^ input[i];
		}
		snprintf(output, output_size, "%02x", hash);
	}

	/* Validate username */
	int is_valid_username(const char *username) {
		if (strlen(username) == 0 || strlen(username) > 32) {
			return 0;
		}

		return 1;
	}

	/* Register a new user */
	/* Register a new user */
int register_user(int client_fd) {
    char buf[BUFSIZE];
    char username[BUFSIZE];
    char password[256];
    char password_hash[64];
    char user_dir[PATH_MAX_LEN];

    while (1) {
        // Prompt for a new username
        snprintf(buf, BUFSIZE, "Enter a new username (or type 'cancel' to exit):\n");
        send_socket(client_fd, buf, strlen(buf));

        // Receive username
        memset(buf, 0, BUFSIZE);
        if (recv_socket(client_fd, buf, BUFSIZE) <= 0) {
            fprintf(stderr, "Failed to receive username\n");
            return -1;
        }
        buf[BUFSIZE - 1] = '\0';
        strncpy(username, buf, BUFSIZE);

        // Allow user to cancel registration
        if (strcmp(username, "cancel") == 0) {
            snprintf(buf, BUFSIZE, "Account creation canceled.\n");
            send_socket(client_fd, buf, strlen(buf));
            return -1;
        }

        // Validate username
        if (!is_valid_username(username)) {
            snprintf(buf, BUFSIZE, "ERROR: Invalid username. Only alphanumeric characters and underscores are allowed.\n");
            send_socket(client_fd, buf, strlen(buf));
            continue;
        }

        // Check if user already exists
        snprintf(user_dir, sizeof(user_dir), "%s/%s", USER_BASE_DIR, username);
        if (access(user_dir, F_OK) == 0) {
            snprintf(buf, BUFSIZE, "ERROR: Username already exists.\n");
            send_socket(client_fd, buf, strlen(buf));
            continue;
        }

        // Prompt for a password
        snprintf(buf, BUFSIZE, "Enter a new password:\n");
        send_socket(client_fd, buf, strlen(buf));

        // Receive password
        memset(buf, 0, BUFSIZE);
        if (recv_socket(client_fd, buf, BUFSIZE) <= 0) {
            fprintf(stderr, "Failed to receive password\n");
            return -1;
        }
        buf[BUFSIZE - 1] = '\0';
        strncpy(password, buf, sizeof(password));

        // Hash the password
        custom_hash(password, password_hash, sizeof(password_hash));

        // Create user directory
        if (mkdir(user_dir, 0755) < 0) {
            perror("mkdir failed");
            snprintf(buf, BUFSIZE, "ERROR: Failed to create user directory.\n");
            send_socket(client_fd, buf, strlen(buf));
            return -1;
        }

        // Store the hashed password
        char password_file[PATH_MAX_LEN];
        snprintf(password_file, sizeof(password_file), "%s/password.txt", user_dir);
        FILE *file = fopen(password_file, "w");
        if (!file) {
            perror("Failed to create password file");
            snprintf(buf, BUFSIZE, "ERROR: Failed to store password.\n");
            send_socket(client_fd, buf, strlen(buf));
            return -1;
        }
        fprintf(file, "%s\n", password_hash);
        fclose(file);

        snprintf(buf, BUFSIZE, "SUCCESS: Account created.\n");
        send_socket(client_fd, buf, strlen(buf));
        return 0;
    }
}


	//* Login function */
	int login(int client_fd, char *username) {
    char buf[BUFSIZE];
    char user_dir[PATH_MAX_LEN];
    char password[256];
    char stored_password_hash[64];
    char input_password_hash[64];
    FILE *file;

    while (1) {
        // Prompt for username
        snprintf(buf, BUFSIZE, "Enter username (or press Enter to create a new account):\n");
        send_socket(client_fd, buf, strlen(buf));

        // Receive username
        memset(buf, 0, BUFSIZE);
        if (recv_socket(client_fd, buf, BUFSIZE) <= 0) {
            fprintf(stderr, "Failed to receive username\n");
            return -1;
        }
        buf[BUFSIZE - 1] = '\0';
        strncpy(username, buf, BUFSIZE);

        // If no username is provided, call register_user
        if (strlen(username) == 0) {
            if (register_user(client_fd) == 0) {
                // After successful registration, loop back to prompt for login
                snprintf(buf, BUFSIZE, "Account created successfully. Please log in with your new credentials.\n");
                send_socket(client_fd, buf, strlen(buf));
                continue;
            } else {
                snprintf(buf, BUFSIZE, "ERROR: Failed to create account.\n");
                send_socket(client_fd, buf, strlen(buf));
                return -1;
            }
        }

        // Validate username
        if (!is_valid_username(username)) {
            snprintf(buf, BUFSIZE, "ERROR: Invalid username. Only alphanumeric characters and underscores are allowed.\n");
            send_socket(client_fd, buf, strlen(buf));
            continue;
        }

        // Check if user directory exists
        snprintf(user_dir, sizeof(user_dir), "%s/%s", USER_BASE_DIR, username);
        if (access(user_dir, F_OK) != 0) {
            snprintf(buf, BUFSIZE, "ERROR: Username not found.\n");
            send_socket(client_fd, buf, strlen(buf));
            continue;
        }

        // Prompt for password
        snprintf(buf, BUFSIZE, "Enter password:\n");
        send_socket(client_fd, buf, strlen(buf));

        // Receive password
        memset(buf, 0, BUFSIZE);
        if (recv_socket(client_fd, buf, BUFSIZE) <= 0) {
            fprintf(stderr, "Failed to receive password\n");
            return -1;
        }
        buf[BUFSIZE - 1] = '\0';
        strncpy(password, buf, sizeof(password));

        // Hash the entered password
        custom_hash(password, input_password_hash, sizeof(input_password_hash));

        // Read the stored password hash
        char password_file[PATH_MAX_LEN];
        snprintf(password_file, sizeof(password_file), "%s/password.txt", user_dir);
        file = fopen(password_file, "r");
        if (!file) {
            perror("Failed to open password file");
            return -1;
        }
        if (!fgets(stored_password_hash, sizeof(stored_password_hash), file)) {
            fprintf(stderr, "Failed to read stored password hash\n");
            fclose(file);
            return -1;
        }
        fclose(file);

        // Compare the hashes
        if (strncmp(stored_password_hash, input_password_hash, sizeof(stored_password_hash)) != 0) {
            snprintf(buf, BUFSIZE, "ERROR: Invalid password.\n");
            send_socket(client_fd, buf, strlen(buf));
            continue;
        }

        // Set working directory to the user's folder
        if (chdir(user_dir) < 0) {
            perror("chdir failed");
            return -1;
        }

        // Send success message
        snprintf(buf, BUFSIZE, "SUCCESS: Logged in as %s.\n", username);
        send_socket(client_fd, buf, strlen(buf));
        return 0; // Successfully logged in
    }
}


	static void limit_resources(void)
	{
		struct rlimit rl;

		/* limit CPU time to 60 seconds per request */
		rl.rlim_cur = 60;
		rl.rlim_max = 60;
		if (setrlimit(RLIMIT_CPU, &rl) < 0) {
			perror("setrlimit(RLIMIT_CPU) failed");
		}

		/* limit maximum memory usage to 200MB */
		rl.rlim_cur = 200 * 1024 * 1024;
		rl.rlim_max = 200 * 1024 * 1024;
		if (setrlimit(RLIMIT_AS, &rl) < 0) {
			perror("setrlimit(RLIMIT_AS) failed");
		}

		/* Limit open file descriptors to 64 */
		rl.rlim_cur = 64;
		rl.rlim_max = 64;
		if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
			perror("setrlimit(RLIMIT_NOFILE) failed");
		}
	}

	static void write_error_output(struct lib *lib)
	{
		/* making a copy from the template */
		char tmpl[] = OUTPUT_TEMPLATE;
		int fd = mkstemp(tmpl);
		if (fd == -1) {
			perror("mkstemp() failed for error output");
			lib->outputfile[0] = '\0';
			return;
		}

		/* setting the output file */
		strncpy(lib->outputfile, tmpl, BUFSIZE - 1);
		lib->outputfile[BUFSIZE - 1] = '\0';
		close(fd);

		/* writing the error output */
		FILE *f = fopen(lib->outputfile, "w");
		if (!f) {
			perror("fopen for error output failed");
			lib->outputfile[0] = '\0';
			return;
		}

		/* case based output */
		if (lib->funcname == NULL || lib->funcname[0] == '\0') {
			fprintf(f, "Error: %s could not be executed.\n", lib->libname);
		}
		else if (lib->filename == NULL || lib->filename[0] == '\0') {
			fprintf(f, "Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
		} else {
			fprintf(f, "Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		}

		fclose(f);
	}

	static int lib_prehooks(struct lib *lib)
	{
		/* TODO: Implement lib_prehooks(). */

		/* allocating memory */
		lib->filename = malloc(BUFSIZE);
		lib->outputfile = malloc(BUFSIZE);
		lib->libname = malloc(BUFSIZE);
		lib->funcname = malloc(BUFSIZE);

		return 0;
	}

	static int lib_load(struct lib *lib)
	{
		/* TODO: Implement lib_load(). */

		/* loading the library */
		lib->handle = dlopen(lib->libname, RTLD_LAZY);
		if (!lib->handle) {
			write_error_output(lib);
			return -1;
		}

		return 0;
	}

	static int lib_execute(struct lib *lib)
	{
		/* TODO: Implement lib_execute(). */

		/* setting the function name */
		if (!lib->funcname || lib->funcname[0] == '\0') {
			strncpy(lib->funcname, "run", sizeof(lib->funcname));
		}

		/* getting the function */
		void *func = dlsym(lib->handle, lib->funcname);
		if (!func) {
			write_error_output(lib); /* error output */
			return -1;
		}

		/* temp template for the stdout */
		char tmpl[] = OUTPUT_TEMPLATE;
		int fd = mkstemp(tmpl);
		if (fd == -1) {
			perror("mkstemp() failed");
			return -1;
		}

		/* setting the output file */
		strncpy(lib->outputfile, tmpl, strlen(tmpl));

		/* redirecting the stdout */
		fflush(stdout);
		int save_stdout = dup(fileno(stdout));
		if (save_stdout == -1) {
			perror("dup() failed");
			return -1;
		}
		if (dup2(fd, fileno(stdout)) == -1) {
			perror("dup2() failed");
			return -1;
		}
		close(fd);

		if (lib->filename && lib->filename[0] != '\0') {
			/* function with an argument */
			lib->p_run = (lambda_param_func_t)func;

			/* running the function in another process in case of failure */
			pid_t pid = fork();
			if (pid == 0) {
				limit_resources(); 						/* limiting the resources */
				alarm(10);								/* setting the alarm */
				setvbuf(stdout, NULL, _IONBF, 0); 		/* setting the buffer */
				lib->p_run(lib->filename); 				/* running the function */
				exit(EXIT_SUCCESS);

			} else {
				int status;
				waitpid(pid, &status, 0);				/* waiting for the child process */
			}

		} else {
			/* function without arguments */
			lib->run = (lambda_func_t)func;

			pid_t pid = fork();
			if (pid == 0) {
				limit_resources(); 						/* limiting the resources */
				alarm(10); 								/* setting the alarm */
				setvbuf(stdout, NULL, _IONBF, 0); 		/* setting the buffer */
				lib->run(); 							/* running the function */
				exit(EXIT_SUCCESS);

			} else {
				int status;
				waitpid(pid, &status, 0);
			}
		}

		/* restoring the stdout */
		fflush(stdout);
		if (dup2(save_stdout, fileno(stdout)) == -1) {
			perror("dup2() failed");
			return -1;
		}
		close(save_stdout);

		return 0;
	}

	static int lib_close(struct lib *lib)
	{
		/* TODO: Implement lib_close(). */

		/* closing the handle */
		if (lib->handle) {
			dlclose(lib->handle);
			lib->handle = NULL;
		}

		return 0;
	}

	static int lib_posthooks(struct lib *lib)
	{
		/* TODO: Implement lib_posthooks(). */
		(void)lib;

		return 0;
	}

	static int lib_run(struct lib *lib)
	{
		int err;

		/* running the lib proccessing */

		err = lib_load(lib);
		if (err)
			return err;

		err = lib_execute(lib);
		if (err)
			return err;

		err = lib_close(lib);
		if (err)
			return err;

		return lib_posthooks(lib);
	}

	static int parse_command(const char *buf, char *name, char *func, char *params)
	{
		int ret;

		ret = sscanf(buf, "%s %s %s", name, func, params);
		if (ret < 0)
			return -1;

		return ret;
	}

	int main(void) {
		int ret;
		struct lib lib;
		int listenfd, connectfd;
		char buf[BUFSIZE];
		char username[BUFSIZE];
		struct sockaddr_un addr;
		socklen_t addr_len = sizeof(addr);

		/* Create the socket */
		listenfd = create_socket();

		/* Initialize and bind the socket */
		memset(&addr, 0, sizeof(struct sockaddr_un));
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
		addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

		unlink(SOCKET_NAME);

		if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("bind() failed");
			close_socket(listenfd);
			return -1;
		}

		if (listen(listenfd, MAX_CLIENTS) < 0) {
			perror("listen() failed");
			close_socket(listenfd);
			return -1;
		}

		while (1) {
			connectfd = accept(listenfd, NULL, NULL);
			if (connectfd < 0) {
				perror("accept() failed");
				continue;
			}

			int pid = fork();
			if (pid == 0) {
				close_socket(listenfd);

				/* Perform login */
				if (login(connectfd, username) < 0) {
					fprintf(stderr, "Login failed\n");
					close_socket(connectfd);
					exit(EXIT_FAILURE);
				}

				/* Receive and process the command */
				memset(buf, 0, BUFSIZE);
				ret = recv_socket(connectfd, buf, BUFSIZE);
				if (ret < 0) {
					perror("recv_socket failed");
					close_socket(connectfd);
					exit(EXIT_FAILURE);
				}
				buf[ret] = '\0';
				printf("Received command: %s\n", buf);

				lib_prehooks(&lib);
				ret = parse_command(buf, lib.libname, lib.funcname, lib.filename);
				if (ret < 0) {
					perror("parse_command failed");
					close_socket(connectfd);
					exit(EXIT_FAILURE);
				}

				ret = lib_run(&lib);
				if (ret < 0) {
					perror("lib_run failed");
					close_socket(connectfd);
					exit(EXIT_FAILURE);
				}

				ret = send_socket(connectfd, lib.outputfile, strlen(lib.outputfile));
				if (ret < 0) {
					perror("send_socket failed");
					close_socket(connectfd);
					exit(EXIT_FAILURE);
				}

				close_socket(connectfd);
				exit(EXIT_SUCCESS);
			} else {
				close_socket(connectfd);
			}
		}

		close_socket(listenfd);
		return 0;
	}