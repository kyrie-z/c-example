#include "public.h"

int main(){

    int sfd, count;
    struct sockaddr_un server_addr;
    char buf[BUF_SIZE]= {0};

    char pipe_path[64] = {0};
    int fdpipe;
    
    sfd = socket(AF_UNIX, SOCK_DGRAM, 0);

    server_addr.sun_family=AF_UNIX;
    strcpy(server_addr.sun_path, SOCK_PATH);

    // snprintf(buf, BUF_SIZE, "tell me my timestamp through the pipe. from client-%d-%d", getpid(), time(NULL));
    snprintf(buf, BUF_SIZE, "client-%d-%ld", getpid(), time(NULL));
    count = sendto(sfd, buf, strlen(buf), 0, (const struct sockaddr*)&server_addr, sizeof(struct sockaddr_un));
    if (count != strlen(buf)){
        printf("senbto error\n");
        return 0;
    }

    snprintf(pipe_path, 64, "%s.%d", CLI_PIPE_PREFIX, getpid());
    if(remove(pipe_path) == -1 && errno != ENOENT){
        printf("remove client pipe error\n");
        return 0;
    }

    if (mkfifo(pipe_path, 0666) == -1){
        printf(" client create pipe error\n");
        return 0;
    }
    fdpipe = open(pipe_path, O_RDONLY);
    if (fdpipe == -1){
        printf(" client open pipe error\n");
        unlink(pipe_path);
        return 0;
    }
    memset(buf, 0, BUF_SIZE);
    read(fdpipe, &buf, BUF_SIZE);
    printf("get resault: %s\n", buf);

    close(fdpipe);
    unlink(pipe_path);
    return 0;
}