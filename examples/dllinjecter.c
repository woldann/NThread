/**
 * MIT License
 *
 * Copyright (c) 2025 Serkan Aksoy
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

/**
 * @file dllinjecter.c
 * @brief Example application demonstrating DLL injection using the NThread library.
 *
 * This test utility performs DLL loading by hijacking an existing thread in the target process,
 * avoiding traditional methods such as CreateRemoteThread or VirtualAllocEx.
 */

#include "ntutils.h"
#include "ntmem.h"
#include <psapi.h>

int64_t get_executable_len(void *addr)
{
#ifdef __WIN32

	// Queries memory information starting from the given address.
	// Calculates the length of the memory region and checks if it's executable.
	MEMORY_BASIC_INFORMATION mbi;

	if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
		return 0;

	DWORD protect = mbi.Protect;
	int64_t ret = (int64_t)(mbi.BaseAddress - addr) + mbi.RegionSize;

	// Return a negative value if the memory region is not executable.
	if (protect != PAGE_EXECUTE_READ && protect != PAGE_EXECUTE_READWRITE) {
		ret *= -1;
	}

	return ret;

#endif /* ifdef __WIN32 */
}

void *find_exec_gadget(uint16_t opcode_tb)
{
#ifdef __WIN32

	// Scans loaded modules of the current process to find a specific gadget (e.g., push/jmp).
	// Searches executable memory areas only.
	HANDLE proc = GetCurrentProcess();
	if (NULL == proc)
		return NULL;

	HMODULE mods[1024];
	DWORD needed;

	if (EnumProcessModules(proc, mods, sizeof(mods), &needed)) {
		unsigned int i;
		register int8_t *addr;

		// Skip the first module (usually the main binary).
		for (i = 1; i < (needed / sizeof(HMODULE)); i++) {
			HMODULE mod = mods[i];
			addr = (void *)mod;
			while (1) {
				int64_t l = get_executable_len(addr);
				if (l == 0)
					break;

				if (l < 0)
					addr -= l;
				else {
					void *ret = memmem(addr, l,
							   (void *)&opcode_tb,
							   sizeof(opcode_tb));
					if (ret != NULL)
						return ret;

					addr += l;
				}
			}
		}
	}

#endif /* ifdef __WIN32 */

	return NULL;
}

#ifdef LOG_LEVEL_1
void warn_gadget()
{
	// Warning: Some registers like RSI and RDI may be used internally by system calls.
	// Hijacking these can lead to instability after DLL injection.
	LOG_WARN(
		"A push gadget was found, but using this register may lead to instability after DLL is loaded.");
}
#endif

int main(int argc, char *argv[])
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

	if (argc < 3) {
#ifdef __WIN32
#ifdef LOG_LEVEL_1
		LOG_INFO(
			"Usage: dllinjecter.exe <thread_id:int> <dll_path:string>");
#endif /* ifdef LOG_LEVEL_1 */
#endif /* ifdef __WIN32 */

		return 0x10;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("neptune initilaized!");
#endif /* ifdef LOG_LEVEL_1 */

	const char *dll_path = argv[2];
	const char *thread_id_str = argv[1];

#ifdef LOG_LEVEL_1
	LOG_INFO("DLL Path(%s)", dll_path);
#endif /* ifdef LOG_LEVEL_1 */

	int thread_id = atoi(thread_id_str);
	if (thread_id < 0) {
#ifdef LOG_LEVEL_1
		LOG_INFO("Invalid thread_id: must be greater than 0");
#endif /* ifdef LOG_LEVEL_1 */

		neptune_destroy();
		return 0x11;
	}

#ifdef __WIN32

	HMODULE kernel32 = GetModuleHandleA("kernel32");
	if (kernel32 == NULL) {
#ifdef LOG_LEVEL_1
		LOG_INFO("GetModuleHandleA failed");
#endif /* ifdef LOG_LEVEL_1 */

		neptune_destroy();
		return 0x20;
	}

	void *load_library_func = GetProcAddress(kernel32, "LoadLibraryW");
	if (load_library_func == NULL) {
#ifdef LOG_LEVEL_1
		LOG_INFO("GetProcAddress failed");
#endif /* ifdef LOG_LEVEL_1 */

		return 0x21;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("LoadLibraryW=%p", load_library_func);
#endif /* ifdef LOG_LEVEL_1 */

#endif /* ifdef __WIN32 */

	nthread_reg_offset_t push_offset;
	void *push_addr;
	void *sleep_addr;

	// Locate an infinite loop gadget: 'jmp $' (opcode: 0xEBFE)
	// This is used to suspend the thread safely.
	sleep_addr = find_exec_gadget(0xfeeb); // jmp $
	if (sleep_addr == NULL) {
		LOG_INFO("Failed to locate a jmp $ gadget.");
		neptune_destroy();
		return 0x40;
	}

	// Locate a usable 'push <reg>' gadget.
	// These are used to manipulate the thread's stack and simulate parameter passing.
	push_addr = find_exec_gadget(0xc353); // push rbx
	if (push_addr != NULL) {
		push_offset = NTHREAD_RBX;
		goto push_addr_found;
	}

	push_addr = find_exec_gadget(0xc355); // push rbp
	if (push_addr != NULL) {
		push_offset = NTHREAD_RBP;
		goto push_addr_found;
	}

	push_addr = find_exec_gadget(0xc356); // push rsi
	if (push_addr != NULL) {
		push_offset = NTHREAD_RSI;

#ifdef LOG_LEVEL_1
		warn_gadget(); // RSI might be used by syscalls or calling conventions.
#endif /* ifdef LOG_LEVEL_1 */

		goto push_addr_found;
	}

	push_addr = find_exec_gadget(0xc357); // push rdi
	if (push_addr == NULL) {
		LOG_INFO("Not found: executable push gadget.");
		neptune_destroy();
		return 0x41;
	}

	push_offset = NTHREAD_RDI;

#ifdef LOG_LEVEL_1
	warn_gadget(); // RDI is also used by system calls or the runtime and may be volatile.
#endif /* ifdef LOG_LEVEL_1 */

push_addr_found:

	// Initialize the ntutils layer for working on the target thread.
	if (HAS_ERR(ntu_init_ex(thread_id, push_offset, push_addr,
				sleep_addr))) {
		LOG_INFO("ntu_init_ex failed");
		neptune_destroy();
		return 0x05;
	}

	size_t dll_path_len = strlen(dll_path);

	// Convert UTF-8 DLL path to UTF-16 since LoadLibraryW expects wide characters.
	int wide_len = MultiByteToWideChar(CP_UTF8, 0, dll_path, dll_path_len,
					   NULL, 0);

	ntmem_t *ntmem = ntm_create_ex((wide_len + 1) * sizeof(wchar_t));
	if (ntmem == NULL) {
		LOG_INFO("ntm_create failed");
		ntu_destroy();
		neptune_destroy();
		return 0x90;
	}

	// Copy the converted string into memory that will be pushed to the target.
	void *local = NTM_LOCAL(ntmem);
	MultiByteToWideChar(CP_UTF8, 0, dll_path, dll_path_len, local,
			    wide_len);
	((wchar_t *)local)[wide_len] = L'\0';

	// Push the DLL path into the remote memory.
	void *dll_path_addr = ntm_push(ntmem);
	if (dll_path_addr == NULL) {
		LOG_INFO("ntm_push failed");
		ntu_destroy();
		neptune_destroy();
		return 0x91;
	}

#ifdef LOG_LEVEL_1
  LOG_INFO("DLL Path Address(%p)", dll_path_addr);
#endif /* ifdef LOG_LEVEL_1 */

	// Call LoadLibraryW inside the target thread context.
	void *load_library_ret = ntu_ucall(load_library_func, dll_path_addr);

	LOG_INFO("Return Value(%p)", load_library_ret);

	ntm_delete(ntmem);
	ntu_destroy();
	neptune_destroy();
	return EXIT_SUCCESS;
}
