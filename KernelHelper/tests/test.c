#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../kernel_agent.h"

int main(){

    int fd, status;
    
    fd = open("/dev/kernel_agent_device", O_RDWR);
    if(fd < 0){
        perror("open");
        return 1;
    }

    status = ioctl(fd, IOCTL_UPDATE_PT);
    if(status < 0){
        perror("ioctl");
        close(fd);
        return 1;
    }
    printf("ioctl IOCTL_UPDATE_PT success\n");
    close(fd);

    return 0;

}