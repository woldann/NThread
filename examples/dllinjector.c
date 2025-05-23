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
 * @file dllinjector.c
 * @brief Example application demonstrating DLL injection using the NThread library.
 *
 * This test utility performs DLL loading by hijacking an existing thread in the target process,
 * avoiding traditional methods such as CreateRemoteThread or VirtualAllocEx.
 */

#include "ntutils.h"
#include "ntmem.h"
#include "nmem.h"

#include <psapi.h>
#include <tlhelp32.h>

nthread_reg_offset_t push_offset;
void *push_addr;
void *sleep_addr;

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

#define CREATE_TOOL_HELP_ERROR 0x2001
#define THREAD32_FIRST_ERROR 0x2002
#define NTU_UPGRADE_ERROR 0x2003
#define WAIT_FOR_SINGLE_OBJECT_ERROR 0x2004
#define NTHREAD_NOT_FOUND_ERROR 0x2005
#define ALLOC_ERROR 0x2006

NMUTEX mutex;

struct aat_args_helper {
  nthread_t nthread;
  ntid_t ntid;
};

void attach_all_threads_helper(void *arg)
{
  struct aat_args_helper *args = (void*) arg;

  nthread_init_ex(&args->nthread, args->ntid, push_offset, push_addr, sleep_addr, 2);
}

nerror_t attach_all_threads(DWORD pid)
{
  THREADENTRY32 te32;
  te32.dwSize = sizeof(THREADENTRY32);

  HANDLE thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (thread_snap == INVALID_HANDLE_VALUE)
    return GET_ERR(CREATE_TOOL_HELP_ERROR);
  
  uint32_t thread_count = 0; 

if (Thread32First(thread_snap, &te32)) {
    do {
      if (te32.th32OwnerProcessID == pid) {
        thread_count++;
      }
    } while (Thread32Next(thread_snap, &te32));
  } else
    return GET_ERR(THREAD32_FIRST_ERROR);

  HANDLE *threads = N_ALLOC(thread_count * sizeof(HANDLE));
  struct aat_args_helper *args_helpers = N_ALLOC(thread_count * sizeof(struct aat_args_helper));

  if (threads == NULL || args_helpers == NULL)
    return GET_ERR(ALLOC_ERROR);

  int32_t created_thread_count = 0;

  if (Thread32First(thread_snap, &te32)) {
    do {
      if (te32.th32OwnerProcessID == pid) {
        ntid_t tid = te32.th32ThreadID;

        struct aat_args_helper *args = args_helpers + created_thread_count;
        args->ntid = tid;
        args->nthread.thread = NULL;

        threads[created_thread_count] = CreateThread(NULL, 0, (void *) attach_all_threads_helper, (void *) args, 0, NULL);
        if (threads[created_thread_count] != NULL)
          created_thread_count++;
      }
    } while (Thread32Next(thread_snap, &te32));
  } else
    return GET_ERR(THREAD32_FIRST_ERROR);

#ifdef LOG_LEVEL_1
  LOG_INFO("Thread Count(%ld)", created_thread_count);
#endif /* ifdef LOG_LEVEL_1 */

  nthread_t *nthread = NULL;
  bool con;
  do {
    con = false;
    for (int32_t i = 0; i < created_thread_count; i++) {
      HANDLE thread = threads[i];
      if (thread == NULL)
        continue;

      con = true;
      DWORD res = WaitForSingleObject(thread, 0);

      if (res == WAIT_TIMEOUT)
        continue;

      if (res == WAIT_OBJECT_0) {
        nthread_t *ret_nthread = &args_helpers[i].nthread;
        if (ret_nthread->thread != NULL) {
          if (nthread == NULL)
            nthread = ret_nthread;
          else {
            nthread_destroy(ret_nthread);
            N_FREE(ret_nthread);
          }
        }
      }

      CloseHandle(thread);
      threads[i] = NULL;
    }
    Sleep(10);
  } while (con);

  N_FREE(threads);

  if (nthread != NULL) {
    if (HAS_ERR(ntu_upgrade(nthread)))
      return GET_ERR(NTU_UPGRADE_ERROR);
  } else
    return GET_ERR(NTHREAD_NOT_FOUND_ERROR);

  N_FREE(args_helpers);
  return N_OK;
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
			"Usage: dllinjector.exe <thread_id:DWORD or process_id:DWORD> <dll_path:string>");
#endif /* ifdef LOG_LEVEL_1 */
#endif /* ifdef __WIN32 */

		return 0x10;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("neptune initilaized!");
#endif /* ifdef LOG_LEVEL_1 */

	const char *dll_path = argv[2];
	const char *id_str = argv[1];

#ifdef LOG_LEVEL_1
	LOG_INFO("DLL Path(%s)", dll_path);
#endif /* ifdef LOG_LEVEL_1 */

#ifdef __WIN32
	 DWORD id = atoi(id_str);
#endif /* ifdef __WIN32 */

	if (id < 0) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("Invalid id: must be greater than 0");
#endif /* ifdef LOG_LEVEL_1 */

		neptune_destroy();
		return 0x11;
	}

#ifdef __WIN32

	HMODULE kernel32 = GetModuleHandleA("kernel32");
	if (kernel32 == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetModuleHandleA failed");
#endif /* ifdef LOG_LEVEL_1 */

		neptune_destroy();
		return 0x20;
	}

	void *load_library_func = GetProcAddress(kernel32, "LoadLibraryA");
	if (load_library_func == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("GetProcAddress failed");
#endif /* ifdef LOG_LEVEL_1 */

		return 0x21;
	}

#ifdef LOG_LEVEL_1
	LOG_INFO("LoadLibraryA=%p", load_library_func);
#endif /* ifdef LOG_LEVEL_1 */

#endif /* ifdef __WIN32 */	

	// Locate an infinite loop gadget: 'jmp $' (opcode: 0xEBFE)
	// This is used to suspend the thread safely.
	sleep_addr = find_exec_gadget(0xfeeb); // jmp $
	if (sleep_addr == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("Failed to locate a jmp $ gadget.");  
#endif /* ifdef LOG_LEVEL_1 */

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

#ifdef LOG_LEVEL_1
		LOG_ERROR("Not found: executable push gadget.");
#endif /* ifdef LOG_LEVEL_1 */

		neptune_destroy();
		return 0x41;
	}

	push_offset = NTHREAD_RDI;

#ifdef LOG_LEVEL_1
	warn_gadget(); // RDI is also used by system calls or the runtime and may be volatile.
#endif /* ifdef LOG_LEVEL_1 */

push_addr_found:
  
#ifdef LOG_LEVEL_1

  LOG_INFO("Push Gadget=%p - %d", push_addr, push_offset);
  LOG_INFO("Sleep Gadget=%p", sleep_addr);

#endif /* ifdef LOG_LEVEL_1 */

	// Initialize the ntutils layer for working on the target thread.
	if (HAS_ERR(ntu_attach_ex(id, push_offset, push_addr,
				sleep_addr))) {

#ifdef LOG_LEVEL_1
		LOG_WARN("ntu_attach_ex failed");
#endif /* ifdef LOG_LEVEL_1 */

    if (HAS_ERR(attach_all_threads(id))) {

#ifdef LOG_LEVEL_1
		  LOG_ERROR("attach_all_threads failed");
#endif /* ifdef LOG_LEVEL_1 */

		  neptune_destroy();
		  return 0x06;
    }
	} 

	size_t dll_path_len = strlen(dll_path);
  size_t dll_path_size = dll_path_len + 1;

	ntmem_t *ntmem = ntm_create_with_alloc_ex(dll_path_size + 1);
	if (ntmem == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("ntm_create failed");
#endif /* ifdef LOG_LEVEL_1 */

		ntu_destroy();
		neptune_destroy();
		return 0x92;
	}

	// Copy the converted string into memory that will be pushed to the target.
	void *local = NTM_LOCAL(ntmem);
  memcpy(local, dll_path, dll_path_size);

	// Push the DLL path into the remote memory.
	void *dll_path_addr = ntm_push(ntmem);
	if (dll_path_addr == NULL) {
#ifdef LOG_LEVEL_1
		LOG_ERROR("ntm_push failed");
#endif /* ifdef LOG_LEVEL_1 */

		ntu_destroy();
		neptune_destroy();
		return 0x93;
	}

#ifdef LOG_LEVEL_1
  LOG_INFO("DLL Path Address(%p)", dll_path_addr);
#endif /* ifdef LOG_LEVEL_1 */

	// Call LoadLibraryA inside the target thread context.
	void *load_library_ret = ntu_ucall(load_library_func, dll_path_addr);

#ifdef LOG_LEVEL_1
	LOG_INFO("Return Value(%p)", load_library_ret);
#endif /* ifdef LOG_LEVEL_1 */

	ntm_delete(ntmem);

	ntu_destroy();
	neptune_destroy();
	return EXIT_SUCCESS;
}
