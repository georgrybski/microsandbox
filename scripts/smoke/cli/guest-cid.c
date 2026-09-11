/* Read the actual virtio-vsock CID inside the disposable smoke guest. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>

int main(void) {
    uint32_t cid = 0;
    int fd = open("/dev/vsock", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open /dev/vsock");
        return 1;
    }
    if (ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) < 0) {
        perror("get local vsock CID");
        close(fd);
        return 1;
    }
    close(fd);
    printf("%u\n", cid);
    return 0;
}
