/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <libgen.h>

#include <dirent.h>

#define RETRY_COUNT 2

#define UEVENT_BUF_SIZE 8192

#define DEVCORE_UEVENT "add@/devices/virtual/devcoredump/devcd"
#define DEVCOREDUMP_PATH "/sys/class/devcoredump"
#define RPROC_SUFFIX "/failing_device/name"
#define NON_DT_RPROC_SUFFIX "/failing_device"

static int parse_args(int argc, char **argv);

#include <syslog.h>

#ifdef USE_GLIB
#include <glib/gprintf.h>
#define strlcat g_strlcat
#define strlcpy g_strlcpy
#endif

#define DUMP_NUM 1
#define ALOGE(format, ...) syslog(LOG_ERR, format, ## __VA_ARGS__)
#define ALOGI(format, ...) syslog(LOG_INFO, format, ## __VA_ARGS__)
#define ALOGW(format, ...) syslog(LOG_WARNING, format, ## __VA_ARGS__)

#define BUFFER_SIZE 0x02000000

#define FILENAME_SIZE 256
#define TIMEBUF_SIZE 21
#define CHK_ELF_LEN 5

#define DUMP_INT_DIR "/var/spool/crash"
#define DUMP_TAIL_BIN ".bin"
#define DUMP_TAIL_ELF ".elf"
#define STR_ELF "ELF"

static char *ramdump_dir;

/*==========================================================================*/
/* Local Function declarations */
/*==========================================================================*/
int check_folder(char *f_name)
{
	int ret = 0;
	struct stat st;

	if ((ret = stat(f_name, &st)) != 0)
		ALOGE( "Directory %s does not exist, ret:%d, error:%d \n", f_name, ret, errno);

	return ret;
}

int create_folder(char *f_name)
{
	int ret = 0;

	if ((ret = mkdir(f_name, S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
		ALOGE("Unable to create %s, ret:%d, error:%d \n", f_name, ret, errno);

	return ret;
}

char *get_current_timestamp(char *buf, int len)
{
	time_t local_time;
	struct tm *tm;

	if (buf == NULL || len < TIMEBUF_SIZE) {
		ALOGE("Invalid timestamp buffer");
		goto get_timestamp_error;
	}

	/* Get current time */
	local_time = time(NULL);
	if (!local_time) {
		ALOGE("Unable to get timestamp");
		goto get_timestamp_error;
	}

	tm = localtime(&local_time);
	if (!tm) {
		ALOGE("Unable to get local time");
		goto get_timestamp_error;
	}

	snprintf(buf, TIMEBUF_SIZE,
		"_%04d-%02d-%02d_%02d-%02d-%02d", tm->tm_year+1900,
		tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min,
		tm->tm_sec);

	return buf;

get_timestamp_error:
	return NULL;
}

int ssr_stop_thread(pthread_t thread_id, int sig)
{
	int ret = 0;
	if (0 == thread_id) return -1;

	/* Signal the thread to exit */
	ret = pthread_kill(thread_id, sig);
	if (ret != 0) {
		ALOGE("Unable to terminate thread %lu, ret:%d, error:%d", thread_id, ret, errno);
	} else {
		if ((ret = pthread_join(thread_id, NULL)) != 0) {
			ALOGE("pthread_join failed for thread %lu, ret:%d, error:%d",
								thread_id, ret, errno);
		}
	}

	return ret;
}

int open_uevent(void)
{
	struct sockaddr_nl addr;
	int sz = 64*UEVENT_BUF_SIZE;
	int s, sb;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = 0xffffffff;

	/*
	*	netlink(7) on nl_pid:
	*	If the application sets it to 0, the kernel takes care of
	*	assigning it.
	*	The kernel assigns the process ID to the first netlink socket
	*	the process opens and assigns a unique nl_pid to every netlink
	*	socket that the process subsequently creates.
	*/
	addr.nl_pid = getpid();

	s = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
	if(s < 0) {
		ALOGE("Creating netlink socket failed, ret:%d, error:%d", s, errno);
		return -1;
	}

	setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));
	sb = bind(s, (struct sockaddr *) &addr, sizeof(addr));
	if(sb < 0) {
		ALOGE("Binding to netlink socket failed, ret:%d, error:%d", sb, errno);
		close(s);
		return -1;
	}

	return s;
}

int uevent_next_event(int fd, char* buffer, int buffer_length)
{
	struct pollfd fds;
	int nr;
	int count;

	while (1) {
		fds.fd = fd;
		fds.events = POLLIN;
		fds.revents = 0;
		nr = poll(&fds, 1, -1);
		if (nr > 0 && (fds.revents & POLLIN)) {
			if(fds.revents & (POLLERR | POLLHUP | POLLNVAL))
				ALOGE("fds.revents: 0x%x", fds.revents);
			count = recv(fd, buffer, buffer_length, 0);
			if (count > 0)
				return count;
			ALOGE("Receiving uevent failed");
		} else if (nr < 0) {
			ALOGE("nr = %d fds.revents = 0x%x err:(%d)", nr, fds.revents, errno);
		}
	}

	return 0;
}

static int read_dump_to_buffer(int *ramdump_fd, char *rd_buf, int buffer_length)
{
	int numBytes = 0, totalBytes = 0;
	do {
		numBytes = read(*ramdump_fd, rd_buf + totalBytes, buffer_length - totalBytes);
		if (numBytes < 0) {
			ALOGE("error while reading ramdump file:%d\n", -errno);
			return -1;
		}
		totalBytes += numBytes;

	} while (numBytes && totalBytes < buffer_length);

	return totalBytes;
}

static int create_ramdump(int ramdump_fd, const char *out_file, bool *rd_fd_closed)
{
	int fd, ret;
	int numBytes = 0, numBytesHeader = 0, totalBytes = 0;
	char output_file[FILENAME_SIZE];
	char *rd_type_buf, *rd_buf;

	rd_type_buf = (char *)calloc(CHK_ELF_LEN, 1);
	if (!rd_type_buf)
		return -errno;

	rd_buf = (char *)calloc(BUFFER_SIZE, 1);
	if (!rd_buf) {
		free(rd_type_buf);
		return -errno;
	}

	/* Read first section of ramdump to determine type */
	numBytesHeader = read(ramdump_fd, rd_type_buf, CHK_ELF_LEN - 1);
	if (numBytesHeader < 0) {
		ret = -errno;
		ALOGE("Failed to read ramdump entry: %d", ret);
		goto open_error;
	}

	*(rd_type_buf + numBytesHeader) = '\0';
	if (strstr(rd_type_buf, STR_ELF))
		snprintf(output_file, FILENAME_SIZE, "%s%s", out_file, DUMP_TAIL_ELF);
	else
		snprintf(output_file, FILENAME_SIZE, "%s%s", out_file, DUMP_TAIL_BIN);

	numBytes = read_dump_to_buffer(&ramdump_fd, rd_buf, BUFFER_SIZE);
	if (numBytes < 0) {
		ret = -errno;
		goto open_error;
	}

	/* For dumps upto BUFFER_SIZE, write and close ramdump FD early */
	if (numBytes < BUFFER_SIZE && rd_fd_closed && !*rd_fd_closed) {
		if (write(ramdump_fd, "1", 1) < 0)
			ALOGE("error while writing 1 to ramdump_fd for %s: err:%d",
					output_file, -errno);
		else {
			*rd_fd_closed = true;
			close(ramdump_fd);
			ALOGE("write successful for ramdump fd for %s", output_file);
		}
	}

	/* Open the output file */
	fd = open(output_file, O_WRONLY | O_CREAT, S_IRUSR);
	if (fd < 0) {
		ALOGE("Failed to open %s, error:%d", output_file, -errno);
		ret = -errno;
		goto open_error;
	}

	/* Write first section ramdump into file */
	ret = write(fd, rd_type_buf, numBytesHeader);
	if (ret < 0) {
		ALOGE("Failed to write to dump file %s err: %d", output_file, -errno);
		ret = -errno;
		goto write_fail;
	} else if (ret < numBytesHeader)
		ALOGE("Failed to write complete data to dump file. Some data may be missing\n");

	totalBytes += ret;

	/* Write buffer data to output file and then read and write remaining data */
	do {
		ret = write(fd, rd_buf, numBytes);
		if (ret < 0) {
			ALOGE("Failed to write to dump file %s error: %d",
					output_file, errno);
			ret = -EIO;
			goto write_fail;
		} else if (ret < numBytes)
			ALOGE("Failed to write complete data to dump file. Some data may be missing\n");

		totalBytes += ret;
	} while(numBytes == BUFFER_SIZE &&
		(numBytes = read_dump_to_buffer(&ramdump_fd, rd_buf, BUFFER_SIZE)) > 0);

	ret = totalBytes;

write_fail:
	fsync(fd);
	close(fd);
open_error:
	free(rd_type_buf);
	free(rd_buf);
	return ret;
}

static void *read_devcore_dump(void *devcd)
{
	char link_buf[FILENAME_SIZE];
	char dev_name[FILENAME_SIZE];
	char file_path1[FILENAME_SIZE];
	char file_path2[FILENAME_SIZE];
	char tm[TIMEBUF_SIZE];
	char *dev_file = NULL;
	char *device_name, *saveptr = NULL;
	int non_dt_path = 0;
	int fd;
	int len;
	long ret;
	bool rd_fd_closed = false;
	char *p;

	snprintf(file_path1, FILENAME_SIZE, "%s/%s%s", DEVCOREDUMP_PATH, devcd, RPROC_SUFFIX);
	snprintf(file_path2, FILENAME_SIZE, "%s/%s%s", DEVCOREDUMP_PATH, devcd, NON_DT_RPROC_SUFFIX);

	/* Wait for some time to make sure device symlinks are created
	 * in devcoredump framework
	 */
	for (size_t i = 0; i < RETRY_COUNT; i++) {
		if (access(file_path1, R_OK) != -1) {
			dev_file = file_path1;
			break;
		} else if (access(file_path2, R_OK) != -1) {
			non_dt_path = 1;
			break;
		}
		ALOGE("%s: file access retry:%d", __func__, i);
		sleep(2);
	}

	if (non_dt_path) {
		len = readlink(file_path2, link_buf, sizeof(link_buf) - 1);
		if (len >= 0) {
			link_buf[len] = '\0';
		} else {
			ALOGE("Unable to read link %s error: %d\n", file_path2, errno);
			ret = -errno;
			goto exit;
		}
		device_name = strrchr(link_buf, '/');
		if (device_name == NULL)
			device_name = strtok_r(link_buf, "\n", &saveptr);
		else
			device_name = strtok_r(device_name+1, "\n", &saveptr);

		if (device_name) {
			strlcpy(dev_name, device_name, sizeof(dev_name));
		} else {
			ALOGE("Unable to read device name in %s.\n", file_path2);
			ret = -ENOENT;
			goto exit;
		}
	} else {
		if (!dev_file) {
			ALOGE("Couldn't find device name in %s and %s\n", file_path1, file_path2);
			ret = -ENOENT;
			goto exit;
		}

		if ((fd = open(dev_file, O_RDONLY)) < 0) {
			ALOGE("Unable to open %s error: %d", dev_file, errno);
			ret = -errno;
			goto exit;
		}

		if (read(fd, dev_name, FILENAME_SIZE - 1) == -1) {
			ALOGE("Failed to read %s error: %d", dev_file, errno);
			ret = -errno;
			goto close_fd;
		}
        dev_name[FILENAME_SIZE - 1] = '\0';
		close(fd);
	}

	if (strstr(dev_name, "microdump")) {
		ALOGI("Microdump skipped by ss_ramdump\n");
		return 0;
	}

	/* strip special characters from remoteproc dev_name*/
	p = strstr(dev_name, "remoteproc");
	if (p) {
		p[strlen("remoteproc")] = '\0';
	}

	snprintf(file_path1, FILENAME_SIZE, "%s/%s/data", DEVCOREDUMP_PATH, devcd);

	/* Wait for ueventd and sepolicy to setup access */
	for (size_t i = 0; i < RETRY_COUNT; i++) {
		if (access(file_path1, R_OK | W_OK) != -1)
			break;

		if (errno != EACCES && errno != ENOENT) {
			ALOGE("Unable to access %s, error: %d\n", file_path1, errno);
			ret = -errno;
			goto exit;
		}
		ALOGE("%s: retrying devcoredump data access after error:%d", __func__, errno);
		sleep(2);
	}

	if ((fd = open(file_path1, O_RDWR)) < 0) {
		ALOGE("Unable to open %s error: %d", file_path1, errno);
		ret = -errno;
		goto exit;
	}

	/* Get current time */
	if (get_current_timestamp(tm, TIMEBUF_SIZE) == NULL) {
		ALOGE("Unable to get timestamp");
		ret = -EIO;
		goto close_ramdump;
	}

	snprintf(file_path2, FILENAME_SIZE, "%s/%s%s", ramdump_dir, dev_name, tm);
	/* Read and copy dumps to output folder */
	ret = create_ramdump(fd, file_path2, &rd_fd_closed);
close_ramdump:
	if (!rd_fd_closed)
		if (write(fd, "1", 1) < 0)
			ALOGE("error while writing 1 in close_ramdump for %s: %d", devcd, errno);
		else
			ALOGE("write successful for close_ramdump for %s", devcd);
close_fd:
	if (!rd_fd_closed)
		close(fd);
exit:
	free(devcd);
	return (void *)ret;
}

static void *mon_devcore_uevents()
{
	int ufd, count, ret;
	char uevent_buf[UEVENT_BUF_SIZE+2];
	char *uevent;
	char *dev;
	pthread_t read_dump_hdl;

	/* open uevent fd */
	ufd = open_uevent();
	if (ufd < 0) {
		ALOGE("Failed to initialize uevent, ufd:%d \n", ufd);
		return NULL;
	}

	while (1) {
		/* Listen for user space event */
		count = uevent_next_event(ufd, uevent_buf, UEVENT_BUF_SIZE);
		if (count <= 0) {
			ALOGE("Uevent msg error; bailing \n");
			break;
		}
		uevent = strstr(uevent_buf, DEVCORE_UEVENT);
		if (uevent) {
			dev = strndup(basename(uevent), FILENAME_SIZE);
			ret = pthread_create(&read_dump_hdl, NULL, read_devcore_dump, dev);
			if (ret) {
				ALOGE("Failed to create dump thread, error:%d\n", ret);
				ALOGE("Device: %s\n", dev);
				free(dev);
			}
		}
	}
	close(ufd);
	return NULL;
}

static int ssr_ramdump_init(char *dump_dir)
{
	int ret = 0;

	/* check if ramdump folder can be created */
	if (check_folder(dump_dir) != 0) {
		ALOGE("Attemping to create %s", dump_dir);
		if ((ret = create_folder(dump_dir)) < 0) {
			ALOGE("Unable to create %s", dump_dir);
			goto open_error;
		}
	}

open_error:
	dump_dir = NULL;

	return ret;
}

static int ssr_ramdump_cleanup()
{
	ramdump_dir = NULL;

	return 0;
}

static void ssr_tool_helper(void)
{
	ALOGI("Usage:./subsystem_ramdump [arg1]");
	ALOGI("Default ramdump location is /var/spool/crash");
	ALOGI("[arg1]: Provide custom ramdump location");
}

static int parse_args(int argc, char **argv)
{
	int ret = 0;

	ssr_tool_helper();
	if (argc == 1) {
		// Use default ramdump location;
		ALOGI(" Using default ramdump location: /var/spool/crash");
        ramdump_dir = DUMP_INT_DIR;
	} else if (argc == 2) {
		ramdump_dir = argv[1];
	} else {
		ALOGE("Too many input arguments");
		ret = -EINVAL;
		goto err_exit;
	}

err_exit:
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	// define event threads
	pthread_t dev_coredump_hdl = 0;

	if ((ret = parse_args(argc, argv)) < 0) {
		ALOGE("Invalid arguments");
		return ret;
	}

	if ((ret = ssr_ramdump_init(ramdump_dir)) < 0) {
		ALOGE("Failed to initialize ramdump");
		return ret;
	}

	/* create thread to collect devcoredump dumps */
	ret = pthread_create(&dev_coredump_hdl, NULL,
				mon_devcore_uevents, NULL);
	if (ret != 0) {
		ALOGE("Creating devcoredump thread failed, error:%d", ret);
		goto cleanup_ramdump;
	}

	/* wait for dev_coredump_hdl thread to terminate */
	ret = pthread_join(dev_coredump_hdl, NULL);
	if (ret != 0) {
		ALOGE("pthread_join failed for thread:%lu, error:%d", dev_coredump_hdl, ret);
	}

cleanup_ramdump:
	ssr_ramdump_cleanup();

	return ret;
}
