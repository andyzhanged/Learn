// SPDX-License-Identifier: GPL-2.0
/*
 * HMM stands for Heterogeneous Memory Management, it is a helper layer inside
 * the linux kernel to help device drivers mirror a process address space in
 * the device. This allows the device to use the same address space which
 * makes communication and data exchange a lot easier.
 *
 * This framework's sole purpose is to exercise various code paths inside
 * the kernel to make sure that HMM performs as expected and to flush out any
 * bugs.
 */

#include "kselftest_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>


/*
 * This is a private UAPI to the kernel test module so it isn't exported
 * in the usual include/uapi/... directory.
 */
#include "test_hmm_uapi.h"
#include <gup_test.h>

struct hmm_buffer {
	void		*ptr;
	void		*mirror;
	unsigned long	size;
	int		fd;
	uint64_t	cpages;
	uint64_t	faults;
};

enum {
	HMM_PRIVATE_DEVICE_ONE,
	HMM_PRIVATE_DEVICE_TWO,
	HMM_COHERENCE_DEVICE_ONE,
	HMM_COHERENCE_DEVICE_TWO,
};

#define TWOMEG		(1 << 21)
#define HMM_BUFFER_SIZE (1024 << 12)
#define HMM_PATH_MAX    64
#define NTIMES		10

#define ALIGN(x, a) (((x) + (a - 1)) & (~((a) - 1)))
/* Just the flags we need, copied from mm.h: */
#define FOLL_WRITE	0x01	/* check pte is writable */
#define FOLL_LONGTERM   0x10000 /* mapping lifetime is indefinite */

FIXTURE(hmm)
{
	int		fd;
	unsigned int	page_size;
	unsigned int	page_shift;
};

FIXTURE_VARIANT(hmm)
{
	int     device_number;
};

FIXTURE_VARIANT_ADD(hmm, hmm_device_private)
{
	.device_number = HMM_PRIVATE_DEVICE_ONE,
};

FIXTURE_VARIANT_ADD(hmm, hmm_device_coherent)
{
	.device_number = HMM_COHERENCE_DEVICE_ONE,
};

FIXTURE(hmm2)
{
	int		fd0;
	int		fd1;
	unsigned int	page_size;
	unsigned int	page_shift;
};

FIXTURE_VARIANT(hmm2)
{
	int     device_number0;
	int     device_number1;
};

FIXTURE_VARIANT_ADD(hmm2, hmm2_device_private)
{
	.device_number0 = HMM_PRIVATE_DEVICE_ONE,
	.device_number1 = HMM_PRIVATE_DEVICE_TWO,
};

FIXTURE_VARIANT_ADD(hmm2, hmm2_device_coherent)
{
	.device_number0 = HMM_COHERENCE_DEVICE_ONE,
	.device_number1 = HMM_COHERENCE_DEVICE_TWO,
};

static int hmm_open(int unit)
{
	char pathname[HMM_PATH_MAX];
	int fd;

	snprintf(pathname, sizeof(pathname), "/dev/hmm_dmirror%d", unit);
	fd = open(pathname, O_RDWR, 0);
	if (fd < 0)
		fprintf(stderr, "could not open hmm dmirror driver (%s)\n",
			pathname);
	return fd;
}

static bool hmm_is_coherent_type(int dev_num)
{
	return (dev_num >= HMM_COHERENCE_DEVICE_ONE);
}

FIXTURE_SETUP(hmm)
{
	self->page_size = sysconf(_SC_PAGE_SIZE);
	self->page_shift = ffs(self->page_size) - 1;

	self->fd = hmm_open(variant->device_number);
	if (self->fd < 0 && hmm_is_coherent_type(variant->device_number))
		SKIP(exit(0), "DEVICE_COHERENT not available");
	ASSERT_GE(self->fd, 0);
}

FIXTURE_SETUP(hmm2)
{
	self->page_size = sysconf(_SC_PAGE_SIZE);
	self->page_shift = ffs(self->page_size) - 1;

	self->fd0 = hmm_open(variant->device_number0);
	if (self->fd0 < 0 && hmm_is_coherent_type(variant->device_number0))
		SKIP(exit(0), "DEVICE_COHERENT not available");
	ASSERT_GE(self->fd0, 0);
	self->fd1 = hmm_open(variant->device_number1);
	ASSERT_GE(self->fd1, 0);
}

FIXTURE_TEARDOWN(hmm)
{
	int ret = close(self->fd);

	ASSERT_EQ(ret, 0);
	self->fd = -1;
}

FIXTURE_TEARDOWN(hmm2)
{
	int ret = close(self->fd0);

	ASSERT_EQ(ret, 0);
	self->fd0 = -1;

	ret = close(self->fd1);
	ASSERT_EQ(ret, 0);
	self->fd1 = -1;
}

static int hmm_dmirror_cmd(int fd,
			   unsigned long request,
			   struct hmm_buffer *buffer,
			   unsigned long npages)
{
	struct hmm_dmirror_cmd cmd;
	int ret;

	/* Simulate a device reading system memory. */
	cmd.addr = (__u64)buffer->ptr;
	cmd.ptr = (__u64)buffer->mirror;
	cmd.npages = npages;

	for (;;) {
		ret = ioctl(fd, request, &cmd);
		if (ret == 0)
			break;
		if (errno == EINTR)
			continue;
		return -errno;
	}
	buffer->cpages = cmd.cpages;
	buffer->faults = cmd.faults;

	return 0;
}

static void hmm_buffer_free(struct hmm_buffer *buffer)
{
	if (buffer == NULL)
		return;

	if (buffer->ptr)
		munmap(buffer->ptr, buffer->size);
	free(buffer->mirror);
	free(buffer);
}

/*
 * Create a temporary file that will be deleted on close.
 */
static int hmm_create_file(unsigned long size)
{
	char path[HMM_PATH_MAX];
	int fd;

	strcpy(path, "/tmp");
	fd = open(path, O_TMPFILE | O_EXCL | O_RDWR, 0600);
	if (fd >= 0) {
		int r;

		do {
			r = ftruncate(fd, size);
		} while (r == -1 && errno == EINTR);
		if (!r)
			return fd;
		close(fd);
	}
	return -1;
}

/*
 * Return a random unsigned number.
 */
static unsigned int hmm_random(void)
{
	static int fd = -1;
	unsigned int r;

	if (fd < 0) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "%s:%d failed to open /dev/urandom\n",
					__FILE__, __LINE__);
			return ~0U;
		}
	}
	read(fd, &r, sizeof(r));
	return r;
}

static void hmm_nanosleep(unsigned int n)
{
	struct timespec t;

	t.tv_sec = 0;
	t.tv_nsec = n;
	nanosleep(&t, NULL);
}

static int hmm_migrate_sys_to_dev(int fd,
				   struct hmm_buffer *buffer,
				   unsigned long npages)
{
	return hmm_dmirror_cmd(fd, HMM_DMIRROR_MIGRATE_TO_DEV, buffer, npages);
}

static int hmm_migrate_dev_to_sys(int fd,
				   struct hmm_buffer *buffer,
				   unsigned long npages)
{
	return hmm_dmirror_cmd(fd, HMM_DMIRROR_MIGRATE_TO_SYS, buffer, npages);
}

/*
 * Simple NULL test of device open/close.
 */
TEST_F(hmm, open_close)
{
}

#if 0
/*
 * Read private anonymous memory.
 */
TEST_F(hmm, anon_read)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;
	int val;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/*
	 * Initialize buffer in system memory but leave the first two pages
	 * zero (pte_none and pfn_zero).
	 */
	i = 2 * self->page_size / sizeof(*ptr);
	for (ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Set buffer permission to read-only. */
	ret = mprotect(buffer->ptr, size, PROT_READ);
	ASSERT_EQ(ret, 0);

	/* Populate the CPU page table with a special zero page. */
	val = *(int *)(buffer->ptr + self->page_size);
	ASSERT_EQ(val, 0);

	/* Simulate a device reading system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_READ, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device read. */
	ptr = buffer->mirror;
	for (i = 0; i < 2 * self->page_size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], 0);
	for (; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Read private anonymous memory which has been protected with
 * mprotect() PROT_NONE.
 */
TEST_F(hmm, anon_read_prot)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Initialize mirror buffer so we can verify it isn't written. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = -i;

	/* Protect buffer from reading. */
	ret = mprotect(buffer->ptr, size, PROT_NONE);
	ASSERT_EQ(ret, 0);

	/* Simulate a device reading system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_READ, buffer, npages);
	ASSERT_EQ(ret, -EFAULT);

	/* Allow CPU to read the buffer so we can check it. */
	ret = mprotect(buffer->ptr, size, PROT_READ);
	ASSERT_EQ(ret, 0);
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], -i);

	hmm_buffer_free(buffer);
}

/*
 * Write private anonymous memory.
 */
TEST_F(hmm, anon_write)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize data that the device will write to buffer->ptr. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Write private anonymous memory which has been protected with
 * mprotect() PROT_READ.
 */
TEST_F(hmm, anon_write_prot)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Simulate a device reading a zero page of memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_READ, buffer, 1);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, 1);
	ASSERT_EQ(buffer->faults, 1);

	/* Initialize data that the device will write to buffer->ptr. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, -EPERM);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], 0);

	/* Now allow writing and see that the zero page is replaced. */
	ret = mprotect(buffer->ptr, size, PROT_WRITE | PROT_READ);
	ASSERT_EQ(ret, 0);

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Check that a device writing an anonymous private mapping
 * will copy-on-write if a child process inherits the mapping.
 */
TEST_F(hmm, anon_write_child)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	pid_t pid;
	int child_fd;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer->ptr so we can tell if it is written. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Initialize data that the device will write to buffer->ptr. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = -i;

	pid = fork();
	if (pid == -1)
		ASSERT_EQ(pid, 0);
	if (pid != 0) {
		waitpid(pid, &ret, 0);
		ASSERT_EQ(WIFEXITED(ret), 1);

		/* Check that the parent's buffer did not change. */
		for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
			ASSERT_EQ(ptr[i], i);
		return;
	}

	/* Check that we see the parent's values. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], -i);

	/* The child process needs its own mirror to its own mm. */
	child_fd = hmm_open(0);
	ASSERT_GE(child_fd, 0);

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(child_fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], -i);

	close(child_fd);
	exit(0);
}

/*
 * Check that a device writing an anonymous shared mapping
 * will not copy-on-write if a child process inherits the mapping.
 */
TEST_F(hmm, anon_write_child_shared)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	pid_t pid;
	int child_fd;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer->ptr so we can tell if it is written. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Initialize data that the device will write to buffer->ptr. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = -i;

	pid = fork();
	if (pid == -1)
		ASSERT_EQ(pid, 0);
	if (pid != 0) {
		waitpid(pid, &ret, 0);
		ASSERT_EQ(WIFEXITED(ret), 1);

		/* Check that the parent's buffer did change. */
		for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
			ASSERT_EQ(ptr[i], -i);
		return;
	}

	/* Check that we see the parent's values. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], -i);

	/* The child process needs its own mirror to its own mm. */
	child_fd = hmm_open(0);
	ASSERT_GE(child_fd, 0);

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(child_fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], -i);

	close(child_fd);
	exit(0);
}

/*
 * Write private anonymous huge page.
 */
TEST_F(hmm, anon_write_huge)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	void *old_ptr;
	void *map;
	int *ptr;
	int ret;

	size = 2 * TWOMEG;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	size = TWOMEG;
	npages = size >> self->page_shift;
	map = (void *)ALIGN((uintptr_t)buffer->ptr, size);
	ret = madvise(map, size, MADV_HUGEPAGE);
	ASSERT_EQ(ret, 0);
	old_ptr = buffer->ptr;
	buffer->ptr = map;

	/* Initialize data that the device will write to buffer->ptr. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	buffer->ptr = old_ptr;
	hmm_buffer_free(buffer);
}
#endif
/*
 * Read numeric data from raw and tagged kernel status files.  Used to read
 * /proc and /sys data (without a tag) and from /proc/meminfo (with a tag).
 */
static long file_read_ulong(char *file, const char *tag)
{
	int fd;
	char buf[2048];
	int len;
	char *p, *q;
	long val;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		/* Error opening the file */
		return -1;
	}

	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len < 0) {
		/* Error in reading the file */
		return -1;
	}
	if (len == sizeof(buf)) {
		/* Error file is too large */
		return -1;
	}
	buf[len] = '\0';

	/* Search for a tag if provided */
	if (tag) {
		p = strstr(buf, tag);
		if (!p)
			return -1; /* looks like the line we want isn't there */
		p += strlen(tag);
	} else
		p = buf;

	val = strtol(p, &q, 0);
	if (*q != ' ') {
		/* Error parsing the file */
		return -1;
	}

	return val;
}
#if 0
/*
 * Write huge TLBFS page.
 */
TEST_F(hmm, anon_write_hugetlbfs)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long default_hsize;
	unsigned long i;
	int *ptr;
	int ret;

	default_hsize = file_read_ulong("/proc/meminfo", "Hugepagesize:");
	if (default_hsize < 0 || default_hsize*1024 < default_hsize)
		SKIP(return, "Huge page size could not be determined");
	default_hsize = default_hsize*1024; /* KB to B */

	size = ALIGN(TWOMEG, default_hsize);
	npages = size >> self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->ptr = mmap(NULL, size,
				   PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
				   -1, 0);
	if (buffer->ptr == MAP_FAILED) {
		free(buffer);
		SKIP(return, "Huge page could not be allocated");
	}

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	/* Initialize data that the device will write to buffer->ptr. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	munmap(buffer->ptr, buffer->size);
	buffer->ptr = NULL;
	hmm_buffer_free(buffer);
}

/*
 * Read mmap'ed file memory.
 */
TEST_F(hmm, file_read)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;
	int fd;
	ssize_t len;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	fd = hmm_create_file(size);
	ASSERT_GE(fd, 0);

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = fd;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	/* Write initial contents of the file. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;
	len = pwrite(fd, buffer->mirror, size, 0);
	ASSERT_EQ(len, size);
	memset(buffer->mirror, 0, size);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ,
			   MAP_SHARED,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Simulate a device reading system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_READ, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Write mmap'ed file memory.
 */
TEST_F(hmm, file_write)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;
	int fd;
	ssize_t len;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	fd = hmm_create_file(size);
	ASSERT_GE(fd, 0);

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = fd;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize data that the device will write to buffer->ptr. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Simulate a device writing system memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device wrote. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	/* Check that the device also wrote the file. */
	len = pread(fd, buffer->mirror, size, 0);
	ASSERT_EQ(len, size);
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Migrate anonymous memory to device private memory.
 */
TEST_F(hmm, migrate)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Migrate memory to device. */
	ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Migrate anonymous memory to device private memory and fault some of it back
 * to system memory, then try migrating the resulting mix of system and device
 * private memory to the device.
 */
/*
* 1. 申请初始化cpu mem，此时cpu mem pfn已存在。
* 2. 模拟dev访问dev mem，触发迁移cpu mem到dev mem。观察cpu mem的pfn，发现已被swapped。
* 3. cpu 访问 cpu mem，触发内容从dev mem迁移到cpu mem。观察cpu mem，发现pfn和之前不一样
*	 可见，内存是重新申请的。且此时dev 的页表会被清楚。
* 4. 模拟dev 访问 dev mem，触发内容从cpu mem迁移会dev mem。
*/
TEST_F(hmm, migrate_fault)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);
	printf("pid is %d\n\n", getpid());
	sleep(10);
	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/*
	* 此时ptr的页表状态
	* 0x7fb9749ff000 : pfn 1865e4   soft-dirty 1 file/shared 0 swapped 0 present 1
	*/

	/* Migrate memory to device. */
	ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* 当cpu mem被迁移到dev mem后，ptr的状态如下：
	* 0x7fb9749ff000 : pfn ffffc01b soft-dirty 1 file/shared 0 swapped 1 present 0
	* swapped变为了1，present变为0。不清楚的是为什么pfn发生了变化。
	*/

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	/* Fault half the pages back to system memory and check them. */
	/*
	* 此时，buffer->ptr的内存已迁移到dev memory，cpu尝试访问，
	* 将会触发缺页中断迁移回cpu mem，流程如下：

	15655   15655   hmm-tests       dmirror_devmem_fault
        b'dmirror_devmem_fault+0x1 [test_hmm]'
		b'do_swap_page
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'do_user_addr_fault+0x1a9 [kernel]'
        b'exc_page_fault+0x81 [kernel]'
        b'asm_exc_page_fault+0x27 [kernel]'

	*/

	/* 与此同时，缺页中断会将dev的页表清除
	* 26464   26464   hmm-tests       dmirror_interval_invalidate
        b'dmirror_interval_invalidate+0x1 [test_hmm]'
        b'migrate_vma_setup+0x20c [kernel]'
        b'dmirror_devmem_fault+0xc6 [test_hmm]'
        b'do_swap_page+0x7b3 [kernel]'
        b'handle_pte_fault+0x227 [kernel]'
        b'__handle_mm_fault+0x3c0 [kernel]'
        b'handle_mm_fault+0x119 [kernel]'
        b'do_user_addr_fault+0x1a9 [kernel]'
        b'exc_page_fault+0x81 [kernel]'
        b'asm_exc_page_fault+0x27 [kernel]'
	*
	*/
	for (i = 0, ptr = buffer->ptr; i < size / (2 * sizeof(*ptr)); ++i)
		ASSERT_EQ(ptr[i], i);

	/*
	* 此时我们在看下ptr的页表状态
	* 0x7fb9749ff000   : pfn 10fd68  soft-dirty 1 file/shared 0 swapped 0 present 1
	* 和最初的相比， pfn发生了变化，可见内存其实是释放后重新申请的。present和swapped恢复。
	*/

	/* Migrate memory to the device again. */
	ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}


TEST_F(hmm, migrate_release)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);
	printf("pid is %d\n", getpid());
	sleep(10);
	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/** buffer->ptr状态
	 * ./pagemap 73538 0x7fa6d4fff000 0x7fa6d4ffff00
0x7fa6d4fff000     : pfn 111dfe           soft-dirty 1 file/shared 0 swapped 0 present 1
	 * 
	*/

	/* Migrate memory to device. */
	ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/** 迁移到dev mem后，buffer->ptr状态
	 * ./pagemap 73538 0x7fa6d4fff000 0x7fa6d4ffff00
0x7fa6d4fff000     : pfn fffffffb         soft-dirty 1 file/shared 0 swapped 1 present 0
	 * 
	*/

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	/* Release device memory. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_RELEASE, buffer, npages);
	ASSERT_EQ(ret, 0);

	/** release dev memory后，buffer->ptr中的内容已从dev迁移回来。
	 *  ./pagemap 73538 0x7fa6d4fff000 0x7fa6d4ffff00
0x7fa6d4fff000     : pfn 1a9e1            soft-dirty 1 file/shared 0 swapped 0 present 1
	*/

	/* Fault pages back to system memory and check them. */

	/**
	* 我看了HMM_DMIRROR_RELEASE的代码，没有看太明白。但从试验得出了如下结论
	 * 当device memory release后，cpu 在访问时(即下面的代码)，将不会触发缺页
	 * 中断将dev memory迁移到cpu中。
	 */
	for (i = 0, ptr = buffer->ptr; i < size / (2 * sizeof(*ptr)); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Migrate anonymous shared memory to device private memory.
 */
	TEST_F(hmm, migrate_shared)
	{
		struct hmm_buffer *buffer;
		unsigned long npages;
		unsigned long size;
		int ret;

		npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >>
			 self->page_shift;
		ASSERT_NE(npages, 0);
		size = npages << self->page_shift;
		printf("pid is %d\n", getpid());
		sleep(10);
		buffer = malloc(sizeof(*buffer));
		ASSERT_NE(buffer, NULL);

		buffer->fd = -1;
		buffer->size = size;
		buffer->mirror = malloc(size);
		ASSERT_NE(buffer->mirror, NULL);

		buffer->ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
				   MAP_SHARED | MAP_ANONYMOUS, buffer->fd, 0);
		ASSERT_NE(buffer->ptr, MAP_FAILED);

		/**
		 * 由于 buffer->ptr并未初始化，所以并没有分配物理内存
		 * 随后，migrate_to_dev的kernel流程中，migrate_vma_setup无法
		 * 找到对应的页表，所以实际上并未发生迁移. 在建立dev页表过程中
		 * ，发现src不存在，也不会建dev页表.
		*/

		/* Migrate memory to device. */
		ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);

		/**
		 * dmirror_do_read找不到dev页表，返回-ENOENT
		 */
		ASSERT_EQ(ret, -ENOENT);

		hmm_buffer_free(buffer);
}



/*
 * Try to migrate various memory types to device private memory.
 */
TEST_F(hmm2, migrate_mixed)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	int *ptr;
	unsigned char *p;
	int ret;
	int val;

	npages = 6;
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	printf("pid is %d\n", getpid());
	sleep(8);
	/* Reserve a range of addresses. */
	buffer->ptr = mmap(NULL, size,
			   PROT_NONE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);
	p = buffer->ptr;

	/* Migrating a protected area should be an error. */
	ret = hmm_migrate_sys_to_dev(self->fd1, buffer, npages);
	/**
	 * dmirror_migrate_to_device 判断没有读的权限，返回EINVAL
	 */
	ASSERT_EQ(ret, -EINVAL);

	/* Punch a hole after the first page address. */
	ret = munmap(buffer->ptr + self->page_size, self->page_size);
	ASSERT_EQ(ret, 0);

	/**
	 * munmap即将第二个page unmap，那么内核怎么处理的？
	 * 通过试验，发现第一个和第二个page均被unmap掉了。vma_lookup
	 * 可以找到第三个page。所以，如下的HMM_DMIRROR_MIGRATE返回-EINVAL。
	*/
	/* We expect an error if the vma doesn't cover the range. */
	ret = hmm_migrate_sys_to_dev(self->fd1, buffer, 3);
	ASSERT_EQ(ret, -EINVAL);

	/**
	 *
	/* Page 2 will be a read-only zero page. */
	ret = mprotect(buffer->ptr + 2 * self->page_size, self->page_size,
				PROT_READ);
	ASSERT_EQ(ret, 0);
	ptr = (int *)(buffer->ptr + 2 * self->page_size);
	/**
	 * page 2 被映射到zero page 
	 */
	val = *ptr + 3;
	ASSERT_EQ(val, 3);

	/* Page 3 will be read-only. */
	ret = mprotect(buffer->ptr + 3 * self->page_size, self->page_size,
				PROT_READ | PROT_WRITE);
	ASSERT_EQ(ret, 0);
	ptr = (int *)(buffer->ptr + 3 * self->page_size);
	/**
	 * page 3 物理页已映射。
	 * 
	*/
	*ptr = val;

	ret = mprotect(buffer->ptr + 3 * self->page_size, self->page_size,
				PROT_READ);
	ASSERT_EQ(ret, 0);

	/* Page 4-5 will be read-write. */
	ret = mprotect(buffer->ptr + 4 * self->page_size, 2 * self->page_size,
				PROT_READ | PROT_WRITE);
	ASSERT_EQ(ret, 0);
	ptr = (int *)(buffer->ptr + 4 * self->page_size);
	*ptr = val;
	ptr = (int *)(buffer->ptr + 5 * self->page_size);
	*ptr = val;

	/* Now try to migrate pages 2-5 to device 1. */
	buffer->ptr = p + 2 * self->page_size;
	ret = hmm_migrate_sys_to_dev(self->fd1, buffer, 4);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, 4);

	/* Page 5 won't be migrated to device 0 because it's on device 1. */
	buffer->ptr = p + 5 * self->page_size;

	/**
	 * page 的状态
	 *./pagemap 91564 0x7f96a8e0b000 0x7f96a8e0c000
		0x7f96a8e0b000     : pfn ffdfff9b         soft-dirty 1 file/shared 0 swapped 1 present 0
	* page 5当前是被swaped，migrate_vma_setup返回的pfn是0, 所以dev页表建立失败
	*。 dmirror_do_read找不到页表，返回-ENOENT。
	*/
	ret = hmm_migrate_sys_to_dev(self->fd0, buffer, 1);
	ASSERT_EQ(ret, -ENOENT);
	buffer->ptr = p;

	buffer->ptr = p;
	hmm_buffer_free(buffer);
}


/*
 * Migrate anonymous memory to device memory and back to system memory
 * multiple times. In case of private zone configuration, this is done
 * through fault pages accessed by CPU. In case of coherent zone configuration,
 * the pages from the device should be explicitly migrated back to system memory.
 * The reason is Coherent device zone has coherent access by CPU, therefore
 * it will not generate any page fault.
 */
TEST_F(hmm, migrate_multiple)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	unsigned long c;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	for (c = 0; c < NTIMES; c++) {
		buffer = malloc(sizeof(*buffer));
		ASSERT_NE(buffer, NULL);

		buffer->fd = -1;
		buffer->size = size;
		buffer->mirror = malloc(size);
		ASSERT_NE(buffer->mirror, NULL);

		buffer->ptr = mmap(NULL, size,
				   PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS,
				   buffer->fd, 0);
		ASSERT_NE(buffer->ptr, MAP_FAILED);

		/* Initialize buffer in system memory. */
		for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
			ptr[i] = i;

		/* Migrate memory to device. */
		ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);
		ASSERT_EQ(ret, 0);
		ASSERT_EQ(buffer->cpages, npages);

		/* Check what the device read. */
		for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
			ASSERT_EQ(ptr[i], i);

		/* Migrate back to system memory and check them. */
		if (hmm_is_coherent_type(variant->device_number)) {
			ret = hmm_migrate_dev_to_sys(self->fd, buffer, npages);
			ASSERT_EQ(ret, 0);
			ASSERT_EQ(buffer->cpages, npages);
		}

		for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
			ASSERT_EQ(ptr[i], i);

		hmm_buffer_free(buffer);
	}
}

/*
 * Read anonymous memory multiple times.
 */

TEST_F(hmm, anon_read_multiple)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	unsigned long c;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	for (c = 0; c < NTIMES; c++) {
		buffer = malloc(sizeof(*buffer));
		ASSERT_NE(buffer, NULL);

		buffer->fd = -1;
		buffer->size = size;
		buffer->mirror = malloc(size);
		ASSERT_NE(buffer->mirror, NULL);

		buffer->ptr = mmap(NULL, size,
				   PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS,
				   buffer->fd, 0);
		ASSERT_NE(buffer->ptr, MAP_FAILED);

		/* Initialize buffer in system memory. */
		for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
			ptr[i] = i + c;

		/* Simulate a device reading system memory. */
		ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_READ, buffer,
				      npages);
		ASSERT_EQ(ret, 0);
		ASSERT_EQ(buffer->cpages, npages);
		ASSERT_EQ(buffer->faults, 1);

		/* Check what the device read. */
		for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
			ASSERT_EQ(ptr[i], i + c);

		hmm_buffer_free(buffer);
	}
}


void *unmap_buffer(void *p)
{
	struct hmm_buffer *buffer = p;

	/* Delay for a bit and then unmap buffer while it is being read. */
	hmm_nanosleep(hmm_random() % 32000);
	munmap(buffer->ptr + buffer->size / 2, buffer->size / 2);
	buffer->ptr = NULL;

	return NULL;
}

/*
 * Try reading anonymous memory while it is being unmapped.
 */
TEST_F(hmm, anon_teardown)
{
	unsigned long npages;
	unsigned long size;
	unsigned long c;
	void *ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	for (c = 0; c < NTIMES; ++c) {
		pthread_t thread;
		struct hmm_buffer *buffer;
		unsigned long i;
		int *ptr;
		int rc;

		buffer = malloc(sizeof(*buffer));
		ASSERT_NE(buffer, NULL);

		buffer->fd = -1;
		buffer->size = size;
		buffer->mirror = malloc(size);
		ASSERT_NE(buffer->mirror, NULL);

		buffer->ptr = mmap(NULL, size,
				   PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS,
				   buffer->fd, 0);
		ASSERT_NE(buffer->ptr, MAP_FAILED);

		/* Initialize buffer in system memory. */
		for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
			ptr[i] = i + c;

		rc = pthread_create(&thread, NULL, unmap_buffer, buffer);
		ASSERT_EQ(rc, 0);

		/* Simulate a device reading system memory. */
		rc = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_READ, buffer,
				     npages);
		if (rc == 0) {
			ASSERT_EQ(buffer->cpages, npages);
			ASSERT_EQ(buffer->faults, 1);

			/* Check what the device read. */
			for (i = 0, ptr = buffer->mirror;
			     i < size / sizeof(*ptr);
			     ++i)
				ASSERT_EQ(ptr[i], i + c);
		}

		pthread_join(thread, &ret);
		hmm_buffer_free(buffer);
	}
}

/*
 * Test memory snapshot without faulting in pages accessed by the device.
 */
TEST_F(hmm, mixedmap)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned char *m;
	int ret;

	npages = 1;
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(npages);
	ASSERT_NE(buffer->mirror, NULL);


	/* Reserve a range of addresses. */
	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE,
			   self->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Simulate a device snapshotting CPU pagetables. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_SNAPSHOT, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* Check what the device saw. */
	m = buffer->mirror;
	ASSERT_EQ(m[0], HMM_DMIRROR_PROT_READ);

	hmm_buffer_free(buffer);
}

/*
 * Test memory snapshot without faulting in pages accessed by the device.
 */

/**
 * 读取页表的属性
*/
TEST_F(hmm2, snapshot)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	int *ptr;
	unsigned char *p;
	unsigned char *m;
	int ret;
	int val;

	npages = 7;
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(npages);
	ASSERT_NE(buffer->mirror, NULL);

	/* Reserve a range of addresses. */
	buffer->ptr = mmap(NULL, size,
			   PROT_NONE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);
	p = buffer->ptr;

	/* Punch a hole after the first page address. */
	ret = munmap(buffer->ptr + self->page_size, self->page_size);
	ASSERT_EQ(ret, 0);

	/* Page 2 will be read-only zero page. */
	ret = mprotect(buffer->ptr + 2 * self->page_size, self->page_size,
				PROT_READ);
	ASSERT_EQ(ret, 0);
	ptr = (int *)(buffer->ptr + 2 * self->page_size);
	val = *ptr + 3;
	ASSERT_EQ(val, 3);

	/* Page 3 will be read-only. */
	ret = mprotect(buffer->ptr + 3 * self->page_size, self->page_size,
				PROT_READ | PROT_WRITE);
	ASSERT_EQ(ret, 0);
	ptr = (int *)(buffer->ptr + 3 * self->page_size);
	*ptr = val;
	ret = mprotect(buffer->ptr + 3 * self->page_size, self->page_size,
				PROT_READ);
	ASSERT_EQ(ret, 0);

	/* Page 4-6 will be read-write. */
	ret = mprotect(buffer->ptr + 4 * self->page_size, 3 * self->page_size,
				PROT_READ | PROT_WRITE);
	ASSERT_EQ(ret, 0);
	ptr = (int *)(buffer->ptr + 4 * self->page_size);
	*ptr = val;

	/* Page 5 will be migrated to device 0. */
	buffer->ptr = p + 5 * self->page_size;
	ret = hmm_migrate_sys_to_dev(self->fd0, buffer, 1);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, 1);

	/* Page 6 will be migrated to device 1. */
	buffer->ptr = p + 6 * self->page_size;
	ret = hmm_migrate_sys_to_dev(self->fd1, buffer, 1);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, 1);

	/* Simulate a device snapshotting CPU pagetables. */
	buffer->ptr = p;
	ret = hmm_dmirror_cmd(self->fd0, HMM_DMIRROR_SNAPSHOT, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* Check what the device saw. */
	m = buffer->mirror;
	/* page 0 和 page 1是被unmap掉的
	* hmm_range_fault填充为 HMM_PFN_ERROR
	*/
	ASSERT_EQ(m[0], HMM_DMIRROR_PROT_ERROR); 
	ASSERT_EQ(m[1], HMM_DMIRROR_PROT_ERROR);

	ASSERT_EQ(m[2], HMM_DMIRROR_PROT_ZERO | HMM_DMIRROR_PROT_READ);
	ASSERT_EQ(m[3], HMM_DMIRROR_PROT_READ);
	ASSERT_EQ(m[4], HMM_DMIRROR_PROT_WRITE);
	if (!hmm_is_coherent_type(variant->device_number0)) {
		ASSERT_EQ(m[5], HMM_DMIRROR_PROT_DEV_PRIVATE_LOCAL |
				HMM_DMIRROR_PROT_WRITE);

		/** 
		 * dmirror_mkentry入参entry是0，page 6已被swaped到dev 1.
		 * entry不是一个有效的PFN，返回 HMM_DMIRROR_PROT_NONE。
		*/
		ASSERT_EQ(m[6], HMM_DMIRROR_PROT_NONE);
	} else {
		ASSERT_EQ(m[5], HMM_DMIRROR_PROT_DEV_COHERENT_LOCAL |
				HMM_DMIRROR_PROT_WRITE);
		ASSERT_EQ(m[6], HMM_DMIRROR_PROT_DEV_COHERENT_REMOTE |
				HMM_DMIRROR_PROT_WRITE);
	}

	hmm_buffer_free(buffer);
}

/*
 * Test the hmm_range_fault() HMM_PFN_PMD flag for large pages that
 * should be mapped by a large page table entry.
 */
TEST_F(hmm, compound)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long default_hsize;
	int *ptr;
	unsigned char *m;
	int ret;
	unsigned long i;

	/* Skip test if we can't allocate a hugetlbfs page. */

	default_hsize = file_read_ulong("/proc/meminfo", "Hugepagesize:");
	if (default_hsize < 0 || default_hsize*1024 < default_hsize)
		SKIP(return, "Huge page size could not be determined");
	default_hsize = default_hsize*1024; /* KB to B */

	size = ALIGN(TWOMEG, default_hsize);
	npages = size >> self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->ptr = mmap(NULL, size,
				   PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
				   -1, 0);
	if (buffer->ptr == MAP_FAILED) {
		free(buffer);
		return;
	}

	buffer->size = size;
	buffer->mirror = malloc(npages);
	ASSERT_NE(buffer->mirror, NULL);

	/* Initialize the pages the device will snapshot in buffer->ptr. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Simulate a device snapshotting CPU pagetables. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_SNAPSHOT, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* Check what the device saw. */
	m = buffer->mirror;
	for (i = 0; i < npages; ++i)
		ASSERT_EQ(m[i], HMM_DMIRROR_PROT_WRITE |
				HMM_DMIRROR_PROT_PMD);

	/* Make the region read-only. */
	ret = mprotect(buffer->ptr, size, PROT_READ);
	ASSERT_EQ(ret, 0);

	/* Simulate a device snapshotting CPU pagetables. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_SNAPSHOT, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* Check what the device saw. */
	m = buffer->mirror;
	for (i = 0; i < npages; ++i)
		ASSERT_EQ(m[i], HMM_DMIRROR_PROT_READ |
				HMM_DMIRROR_PROT_PMD);

	munmap(buffer->ptr, buffer->size);
	buffer->ptr = NULL;
	hmm_buffer_free(buffer);
}

/*
 * Test two devices reading the same memory (double mapped).
 */
TEST_F(hmm2, double_map)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = 6;
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(npages);
	ASSERT_NE(buffer->mirror, NULL);
	printf("pid is %d\n", getpid());
	sleep(8);
	/* Reserve a range of addresses. */
	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;
	/**
	 *  ptr 物理内存状态
	 * 	0x7f56fdf56000 : pfn 112d66 soft -
			 dirty 1 file / shared 0 swapped 0 present 1
	*/

	/* Make region read-only. */
	ret = mprotect(buffer->ptr, size, PROT_READ);
	ASSERT_EQ(ret, 0);

	/* Simulate device 0 reading system memory. */
	ret = hmm_dmirror_cmd(self->fd0, HMM_DMIRROR_READ, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);
	/**
	 *  ptr 物理内存状态
	 * 	0x7f56fdf56000 : pfn 112d66 soft -
			 dirty 1 file / shared 0 swapped 0 present 1
	 * 可见，淡出的读，并不会将page swaped到dev。		 
	*/

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	/* Simulate device 1 reading system memory. */
	ret = hmm_dmirror_cmd(self->fd1, HMM_DMIRROR_READ, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	/* Migrate pages to device 1 and try to read from device 0. */
	ret = hmm_migrate_sys_to_dev(self->fd1, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/** 至此 cpu mem的page被swaped到了dev 1 的mem。
	 * zhanged-hyper# pagemap # ./pagemap 103985 0x7ff0791bd000 0x7ff0791bf000
0x7ff0791bd000     : pfn ffdfff5c         soft-dirty 1 file/shared 0 swapped 1 present 0
0x7ff0791be000     : pfn ffdfff7c         soft-dirty 1 file/shared 0 swapped 1 present 0
	*/

	ret = hmm_dmirror_cmd(self->fd0, HMM_DMIRROR_READ, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	ASSERT_EQ(buffer->faults, 1);
	/**
	 * zhanged-hyper# pagemap # ./pagemap 103985 0x7ff0791bd000 0x7ff0791bf000
0x7ff0791bd000     : pfn 116d08           soft-dirty 1 file/shared 0 swapped 0 present 1
0x7ff0791be000     : pfn 116d09           soft-dirty 1 file/shared 0 swapped 0 present 1
	 * 可见，当dev 0尝试读cpu mem, mem被从dev 1 swaped会到了cpu mem。
	*/

	/* Check what device 0 read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	hmm_buffer_free(buffer);
}

/*
 * Basic check of exclusive faulting.
 */
TEST_F(hmm, exclusive)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);
	printf("pid is %d\n", getpid());
	sleep(10);
	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/**
	 * zhanged-hyper# pagemap # ./pagemap 107495 0x7fe05c5ff000 0x7fe05c5fff00
0x7fe05c5ff000     : pfn 32390            soft-dirty 1 file/shared 0 swapped 0 present 1
	*/
	/* Map memory exclusively for device access. */

	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_EXCLUSIVE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/**
	 * zhanged-hyper# pagemap # ./pagemap 107495 0x7fe05c5ff000 0x7fe05c5fff00
0x7fe05c5ff000     : pfn 64721d           soft-dirty 1 file/shared 0 swapped 1 present 0
	*/

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	/* Fault pages back to system memory and check them. */
	/**
	 * 1. 迁移mem从dev 会到cpu mem。令我奇怪的是该步骤和之前的case不一样，并未触发dmirror_devmem_fault。
	 * 	 那么是如何迁移回来的呢？而且迁移回来的pfn也是和迁移之前一样的，这和之前的case也不同。
	 * 2. 校验结果
	 * 3. 对ptr的每个值加1.
	*/
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i]++, i);

	/**
	 * zhanged-hyper# pagemap # ./pagemap 107495 0x7fe05c5ff000 0x7fe05c5fff00
	0x7fe05c5ff000     : pfn 32390            soft-dirty 1 file/shared 0 swapped 0 present 1
	*/

	/*校验加1是否成功*/
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i+1);

	/* Check atomic access revoked */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_CHECK_EXCLUSIVE, buffer, npages);
	ASSERT_EQ(ret, 0);

	hmm_buffer_free(buffer);
}

TEST_F(hmm, exclusive_mprotect)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Map memory exclusively for device access. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_EXCLUSIVE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	ret = mprotect(buffer->ptr, size, PROT_READ);
	ASSERT_EQ(ret, 0);

	/* Simulate a device writing system memory. */
	/**
	 * 由于只有读权限，当hmm_range_fault查找页表(with HMM_PFN_REQ_WRITE)时，返回-EPERM。
	 * 
	*/
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_WRITE, buffer, npages);
	ASSERT_EQ(ret, -EPERM);

	hmm_buffer_free(buffer);
}


/*
 * Check copy-on-write works.
 */
TEST_F(hmm, exclusive_cow)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;

	npages = ALIGN(HMM_BUFFER_SIZE, self->page_size) >> self->page_shift;
	ASSERT_NE(npages, 0);
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Map memory exclusively for device access. */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_EXCLUSIVE, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	fork();

	/* Fault pages back to system memory and check them. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i]++, i);

	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i+1);

	hmm_buffer_free(buffer);
}

static int gup_test_exec(int gup_fd, unsigned long addr, int cmd,
			 int npages, int size, int flags)
{
	struct gup_test gup = {
		.nr_pages_per_call	= npages,
		.addr			= addr,
		.gup_flags		= FOLL_WRITE | flags,
		.size			= size,
	};

	if (ioctl(gup_fd, cmd, &gup)) {
		perror("ioctl on error\n");
		return errno;
	}

	return 0;
}

/*
 * Test get user device pages through gup_test. Setting PIN_LONGTERM flag.
 * This should trigger a migration back to system memory for both, private
 * and coherent type pages.
 * This test makes use of gup_test module. Make sure GUP_TEST_CONFIG is added
 * to your configuration before you run it.
 */
TEST_F(hmm, hmm_gup_test)
{
	struct hmm_buffer *buffer;
	int gup_fd;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;
	unsigned char *m;

	gup_fd = open("/sys/kernel/debug/gup_test", O_RDWR);
	if (gup_fd == -1)
		SKIP(return, "Skipping test, could not find gup_test driver");

	npages = 4;
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Migrate memory to device. */
	ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	/* Check what the device read. */
	for (i = 0, ptr = buffer->mirror; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	ASSERT_EQ(gup_test_exec(gup_fd,
				(unsigned long)buffer->ptr,
				GUP_BASIC_TEST, 1, self->page_size, 0), 0);
	ASSERT_EQ(gup_test_exec(gup_fd,
				(unsigned long)buffer->ptr + 1 * self->page_size,
				GUP_FAST_BENCHMARK, 1, self->page_size, 0), 0);
	ASSERT_EQ(gup_test_exec(gup_fd,
				(unsigned long)buffer->ptr + 2 * self->page_size,
				PIN_FAST_BENCHMARK, 1, self->page_size, FOLL_LONGTERM), 0);
	ASSERT_EQ(gup_test_exec(gup_fd,
				(unsigned long)buffer->ptr + 3 * self->page_size,
				PIN_LONGTERM_BENCHMARK, 1, self->page_size, 0), 0);

	/* Take snapshot to CPU pagetables */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_SNAPSHOT, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	m = buffer->mirror;
	if (hmm_is_coherent_type(variant->device_number)) {
		ASSERT_EQ(HMM_DMIRROR_PROT_DEV_COHERENT_LOCAL | HMM_DMIRROR_PROT_WRITE, m[0]);
		ASSERT_EQ(HMM_DMIRROR_PROT_DEV_COHERENT_LOCAL | HMM_DMIRROR_PROT_WRITE, m[1]);
	} else {
		ASSERT_EQ(HMM_DMIRROR_PROT_WRITE, m[0]);
		ASSERT_EQ(HMM_DMIRROR_PROT_WRITE, m[1]);
	}
	ASSERT_EQ(HMM_DMIRROR_PROT_WRITE, m[2]);
	ASSERT_EQ(HMM_DMIRROR_PROT_WRITE, m[3]);
	/*
	 * Check again the content on the pages. Make sure there's no
	 * corrupted data.
	 */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ASSERT_EQ(ptr[i], i);

	close(gup_fd);
	hmm_buffer_free(buffer);
}
#endif

/*
 * Test copy-on-write in device pages.
 * In case of writing to COW private page(s), a page fault will migrate pages
 * back to system memory first. Then, these pages will be duplicated. In case
 * of COW device coherent type, pages are duplicated directly from device
 * memory.
 */
TEST_F(hmm, hmm_cow_in_device)
{
	struct hmm_buffer *buffer;
	unsigned long npages;
	unsigned long size;
	unsigned long i;
	int *ptr;
	int ret;
	unsigned char *m;
	pid_t pid;
	int status;

	npages = 4;
	size = npages << self->page_shift;

	buffer = malloc(sizeof(*buffer));
	ASSERT_NE(buffer, NULL);

	buffer->fd = -1;
	buffer->size = size;
	buffer->mirror = malloc(size);
	ASSERT_NE(buffer->mirror, NULL);

	buffer->ptr = mmap(NULL, size,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   buffer->fd, 0);
	ASSERT_NE(buffer->ptr, MAP_FAILED);

	/* Initialize buffer in system memory. */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Migrate memory to device. */

	ret = hmm_migrate_sys_to_dev(self->fd, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);

	pid = fork();
	if (pid == -1)
		ASSERT_EQ(pid, 0);
	if (!pid) {
		/* Child process waitd for SIGTERM from the parent. */
		while (1) {
		}
		perror("Should not reach this\n");
		exit(0);
	}
	/* Parent process writes to COW pages(s) and gets a
	 * new copy in system. In case of device private pages,
	 * this write causes a migration to system mem first.
	 */
	for (i = 0, ptr = buffer->ptr; i < size / sizeof(*ptr); ++i)
		ptr[i] = i;

	/* Terminate child and wait */
	EXPECT_EQ(0, kill(pid, SIGTERM));
	EXPECT_EQ(pid, waitpid(pid, &status, 0));
	EXPECT_NE(0, WIFSIGNALED(status));
	EXPECT_EQ(SIGTERM, WTERMSIG(status));

	/* Take snapshot to CPU pagetables */
	ret = hmm_dmirror_cmd(self->fd, HMM_DMIRROR_SNAPSHOT, buffer, npages);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(buffer->cpages, npages);
	m = buffer->mirror;
	for (i = 0; i < npages; i++)
		ASSERT_EQ(HMM_DMIRROR_PROT_WRITE, m[i]);

	hmm_buffer_free(buffer);
}

TEST_HARNESS_MAIN
