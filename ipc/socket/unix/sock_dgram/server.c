#include "public.h"

int main(){
    struct sockaddr_un server_addr;
    int sfd, count;
    char buf[BUF_SIZE];


    sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sfd == -1){
        printf("socket create error!!\n");
        return 0;
    }

    if(remove(SOCK_PATH) == -1 && errno != ENOENT){
        printf("remove socket error\n");
        return 0;
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCK_PATH, sizeof(server_addr.sun_path)-1 );

    if (bind(sfd, (const struct sockaddr*)&server_addr, sizeof(struct sockaddr_un)) == -1){
        printf("bind error!!\n");
        return 0;
    }

    for(;;){
        // len = sizeof(struct sockaddr_un);
        // count = recvfrom(sfd, buf, BUF_SIZE, 0, (struct sockaddr*)&cli_addr, &len);
        memset(buf, 0, BUF_SIZE);
        count = recv(sfd, buf, BUF_SIZE, 0);
        if (count == -1){
            printf("recvfrom error\n");
        }
        printf("get request: %s, size: %ld\n", buf, strlen(buf));

        int timestamp, cli_pid;
        int fdpipe;
        char pipe_path[64];
        char revc_buf[BUF_SIZE];
        pid_t pid = fork();
        switch(pid){
            case -1:
                printf("fork error\n");
                break;
            case 0:
                close(sfd);
                //获取时间戳。发送pipe
                sscanf(buf, "%*[a-z]-%d-%d", &cli_pid, &timestamp);
                snprintf(pipe_path, 64, "%s.%d", CLI_PIPE_PREFIX, cli_pid);
                fdpipe = open(pipe_path, O_WRONLY);
                if (fdpipe == -1){
                    printf("open cli pipe error\n");
                    return 0;
                }
                snprintf(revc_buf, BUF_SIZE, "%d", timestamp);
                write(fdpipe, revc_buf, strlen(revc_buf));
                close(fdpipe);
                return 0;

            default:
                waitpid(pid, NULL, 0);
        }
    }


    close(sfd);
    remove(server_addr.sun_path);
    return 0;
}