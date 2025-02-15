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

int main(void)
{
	/* TODO: Implement server connection. */

	int ret;
	struct lib lib;
	int listenfd, connectfd;
	char buf[BUFSIZE];
	struct sockaddr_un addr;
	socklen_t addr_len = sizeof(addr);

	/* creating the socket */
	listenfd = create_socket();

	/* initializing and adding the socket to the family */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

	/* unlinking the socket */
	unlink(SOCKET_NAME);

	/* binding the socket */
	if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind() failed");
		close_socket(listenfd);
		return -1;
	}

	/* listening to the socket */
	if (listen(listenfd, MAX_CLIENTS) < 0) {
		perror("listen() failed");
		close_socket(listenfd);
		return -1;
	}

	while (1) {
		/* accepting the connection */
		connectfd = accept(listenfd, NULL, NULL);
		if (connectfd < 0) {
			perror("accept() failed");
			close_socket(listenfd);
			close_socket(connectfd);
			return -1;
		}

		/* forking to handle clients in parallel */
		int pid = fork();
		if (pid == 0) {
			/* TODO - get message from client */

			/* receiving the message */
			ret = recv_socket(connectfd, buf, BUFSIZE);
			if (ret < 0) {
				close_socket(listenfd);
				close_socket(connectfd);
				return -1;
			}
			buf[ret] = '\0';
			printf("Received: %s\n", buf);

			/* initializing the lib */
			lib_prehooks(&lib);

			/* TODO - parse message with parse_command and populate lib */

			/* parsing the commmand */
			ret = parse_command(buf, lib.libname, lib.funcname, lib.filename);
			if (ret < 0) {
				close_socket(listenfd);
				close_socket(connectfd);
				return -1;
			}

			/* TODO - handle request from client */

			/* running the library */
			ret = lib_run(&lib);

			/* sending the output to the client */
			ret = send_socket(connectfd, lib.outputfile, strlen(lib.outputfile));
			if (ret < 0) {
				close_socket(listenfd);
				close_socket(connectfd);
				return -1;
			}
			exit(EXIT_SUCCESS);

		} else {
			close_socket(connectfd);
		}
	}

	/* closing the socket */
	if (lib.filename) {
        free(lib.filename);
        lib.filename = NULL;
    }
    if (lib.outputfile) {
        free(lib.outputfile);
        lib.outputfile = NULL;
    }
    if (lib.libname) {
        free(lib.libname);
        lib.libname = NULL;
    }
    if (lib.funcname) {
        free(lib.funcname);
        lib.funcname = NULL;
    }
	close_socket(listenfd);
	close_socket(connectfd);

	return 0;
}