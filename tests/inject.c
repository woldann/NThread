/**
 * MIT License
 *
 * Copyright (c) 2024, 2025 Serkan Aksoy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "neptune.h"
#include "nerror.h"
#include "nthread.h"
#include "ntutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int8_t push_sleep[] = { 0x55, 0xc3, 0xeb, 0xfe };

void thread_func(void)
{
	while (1)
		Sleep(10);
}

int main(int argc, char *argv[])
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

	LOG_INFO("Neptune initilaized!");

	DWORD tid;
	HANDLE create_thread = CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)thread_func, NULL, 0, &tid);
	if (create_thread == NULL) {
		LOG_ERROR("Thread creation failed");
		neptune_destroy();
		return 0x01;
	}

#ifdef _WIN32

	HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (thread == NULL) {
		LOG_ERROR("Thread not found");
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x30;
	}

	DWORD pid = GetProcessIdOfThread(thread);
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (proc == NULL) {
		LOG_ERROR("Process not found");
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x31;
	}

	void *push_sleep_addr = VirtualAllocEx(proc, NULL, sizeof(push_sleep),
					       MEM_RESERVE | MEM_COMMIT,
					       PAGE_EXECUTE_READWRITE);

	if (push_sleep_addr == NULL) {
		LOG_ERROR("Memory allocation failed");
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x32;
	}

	SIZE_T write_len;
	if (!WriteProcessMemory(proc, push_sleep_addr, push_sleep,
				sizeof(push_sleep), &write_len)) {
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x33;
	}

#endif /* ifdef _WIN32 */

	LOG_INFO("%lld bytes writed to %ld", write_len, pid);

	if (HAS_ERR(ntu_attach(tid, push_sleep_addr,
			       (void *)((int8_t *)push_sleep_addr + 2)))) {
		LOG_INFO("ntu_init failed");
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x06;
	}

	LOG_INFO("ntutils initilaized");

	char test_str[] = "test string";
	void *str_addr = ntu_alloc_str(test_str);
	if (str_addr == NULL) {
		ntu_destroy();
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x34;
	}

	int8_t buffer[64] = { 0 };
	if (HAS_ERR(ntu_read_memory(str_addr, buffer, sizeof(test_str)))) {
		ntu_destroy();
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x35;
	}

	ntu_free(str_addr);
	LOG_INFO("Buffer: %s", buffer);
	if (strcmp((void *)buffer, test_str) != 0) {
		ntu_destroy();
		neptune_destroy();
		CloseHandle(create_thread);
		return 0x36;
	}

	LOG_INFO("String readed from target process");

	ntu_destroy();
	LOG_INFO("ntutils destroyed");
	LOG_INFO("Test successful");

	neptune_destroy();
	CloseHandle(create_thread);
	return EXIT_SUCCESS;
}
