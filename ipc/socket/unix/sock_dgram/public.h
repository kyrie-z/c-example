#include<sys/socket.h>
#include<sys/un.h>

#include <sys/types.h>
#include <unistd.h>

#include<stdio.h>
#include<errno.h>

#include <time.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>

#include<stdio.h> 
#include<sys/wait.h>

#define BUF_SIZE 128

#define SOCK_PATH "/tmp/server_dgram.sock"
#define CLI_PIPE_PREFIX "/tmp/client_pipe"