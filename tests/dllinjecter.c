/**
 * Copyright (C) 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#include "neptune.h"
#include "nerror.h"
#include "nthread.h"
#include "ntutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int8_t push_sleep[] = { 0x55, 0xc3, 0xeb, 0xfe };

int main(int argc, char *argv[])
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

	LOG_INFO("neptune initilaized!");

  void *libc_base = ntu_get_libc_base();
  if (libc_base == NULL) {
    LOG_INFO("ntu_get_libc_base failed");
    return 0x20;
  }
  LOG_INFO("libc_base=%p", libc_base);

	ntid_t tid;
	printf("enter tid: ");
	scanf("%ld", &tid);

#ifdef __WIN32
	HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (thread == NULL) {
		LOG_ERROR("Thread not found");
		neptune_destroy();
		return 0x30;
	}

	DWORD pid = GetProcessIdOfThread(thread);
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (proc == NULL) {
		neptune_destroy();
		return 0x31;
	}

	void *push_sleep_addr = VirtualAllocEx(proc, NULL, sizeof(push_sleep),
					       MEM_RESERVE | MEM_COMMIT,
					       PAGE_EXECUTE_READWRITE);

	if (push_sleep_addr == NULL) {
		neptune_destroy();
		return 0x32;
	}

	SIZE_T write_len;
	if (!WriteProcessMemory(proc, push_sleep_addr, push_sleep,
				sizeof(push_sleep), &write_len)) {
		neptune_destroy();
		return 0x33;
	}

	LOG_INFO("%lld bytes writed to %ld", write_len, pid);
	RET_ERR(ntu_init(tid, push_sleep_addr, push_sleep_addr + 2));

	LOG_INFO("ntutils initilaized");

#endif /* ifdef __WIN32 */

	char test_str[] = "test string";
	void *str_addr = ntu_alloc_str(test_str);
	if (str_addr == NULL) {
		ntu_destroy();
		neptune_destroy();
		return 0x34;
	}

	int8_t buffer[64] = { 0 };
	if (HAS_ERR(ntu_read_memory(str_addr, buffer, sizeof(test_str)))) {
		ntu_destroy();
		neptune_destroy();
		return 0x35;
	}

	ntu_free(str_addr);
	LOG_INFO("Buffer: %s", buffer);
	if (strcmp((void *)buffer, test_str) != 0) {
		ntu_destroy();
		neptune_destroy();
		return 0x36;
	}

	ntu_destroy();
	neptune_destroy();
	return EXIT_SUCCESS;
}
