/**
 * Copyright (C) 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

/**
 * @file dllinjecter.c
 * @brief Example application demonstrating DLL injection using the NThread library.
 *
 * This test utility performs DLL loading by hijacking an existing thread in the target process,
 * avoiding traditional methods such as CreateRemoteThread or VirtualAllocEx.
 * 
 * Instead, it utilizes a stealthy approach based on:
 * - Thread context manipulation
 * - Reuse of existing executable memory (push/jmp gadgets)
 * - NThread abstraction layer (ntutils, ntmem, nthread modules)
 *
 * Designed for and tested on Windows x64 systems.
 */

#include "neptune.h"
#include "nerror.h"
#include "nthread.h"
#include "ntutils.h"
#include "ntmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

int64_t get_executable_len(void *addr) {

#ifdef __WIN32

  MEMORY_BASIC_INFORMATION mbi;

  if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
    return 0;

  DWORD protect = mbi.Protect;
  int64_t ret = (int64_t) (mbi.BaseAddress - addr) + mbi.RegionSize;

  if (protect != PAGE_EXECUTE_READ &&
    protect != PAGE_EXECUTE_READWRITE) {
    ret *= -1;
  }

  return ret;

#endif /* ifdef __WIN32 */

}

void *find_exec_gadget(uint16_t instruction_tb)
{

#ifdef __WIN32

  HANDLE proc = GetCurrentProcess();
  if (NULL == proc)
    return NULL;

  HMODULE mods[1024];
  DWORD needed;

  if(EnumProcessModules(proc, mods, sizeof(mods), &needed)) {
    unsigned int i;
    register int8_t *addr;

    for (i = 1; i < (needed / sizeof(HMODULE)); i++) {
      HMODULE mod = mods[i];
      addr = (void *) mod;
      while (1) {
        int64_t l = get_executable_len(addr);
        if (l == 0)
          break;
        
        if (l < 0)
         addr -= l;
        else {
          void *ret = memmem(addr, l, (void *)&instruction_tb, sizeof(instruction_tb));
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

void warn_gadget()
{
  LOG_WARN("A push gadget was found, but using this register may lead to instability after DLL is loaded.");
}

#ifdef __WIN32

uint16_t push_code = 0xc353; // push rbx
nthread_reg_offset_t offsets[] = {NTHREAD_RBX, NTHREAD_RSP, NTHREAD_RBP, NTHREAD_RSI, NTHREAD_RDI};

#endif /* ifdef __WIN32 */

int main(int argc, char *argv[])
{
	if (HAS_ERR(neptune_init()))
		return EXIT_FAILURE;

  if (argc < 3) {

#ifdef __WIN32
#ifdef LOG_LEVEL_1
  LOG_INFO("Usage: dllinjecter.exe <thread_id:int> <dll_path:string>");
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
    LOG_INFO("thread_id must bigger than 0");
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
  LOG_INFO("LoadLibraryA=%p", load_library_func);
#endif /* ifdef LOG_LEVEL_1 */

#endif /* ifdef __WIN32 */

  nthread_reg_offset_t push_offset;
  void *push_addr;
  void *sleep_addr;
  
  sleep_addr = find_exec_gadget(0xfeeb); // jmp $
  if (sleep_addr == NULL) {
#ifdef LOG_LEVEL_1
    LOG_INFO("Failed to locate an executable memory region with a valid push <reg> gadget.");
#endif /* ifdef LOG_LEVEL_1 */

    neptune_destroy();
    return 0x40;
  }

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
    warn_gadget();
#endif /* ifdef LOG_LEVEL_1 */

    goto push_addr_found;
  }
  
  push_addr = find_exec_gadget(0xc357); // push rdi
  if (push_addr == NULL) {
#ifdef LOG_LEVEL_1
    LOG_INFO("not founded executable push_addr");
#endif /* ifdef LOG_LEVEL_1 */

    neptune_destroy();
    return 0x41;
  } 

  push_offset = NTHREAD_RDI;

#ifdef LOG_LEVEL_1
  warn_gadget();
#endif /* ifdef LOG_LEVEL_1 */

push_addr_found:
    
	if (HAS_ERR(ntu_init_ex(thread_id, push_offset, push_addr, sleep_addr))) {
#ifdef LOG_LEVEL_1
	  LOG_INFO("ntu_init_ex failed");
#endif /* ifdef LOG_LEVEL_1 */

    neptune_destroy();
    return 0x05;
  }

#ifdef LOG_LEVEL_1
	LOG_INFO("ntutils initilaized");
#endif /* ifdef LOG_LEVEL_1 */

#ifdef __WIN32

  size_t dll_path_len = strlen(dll_path);
  int wide_len = MultiByteToWideChar(CP_UTF8, 0, dll_path, dll_path_len, NULL, 0);
  ntmem_t *ntmem = ntm_create_ex((wide_len + 1) * sizeof(wchar_t));
  if (ntmem == NULL) {
#ifdef LOG_LEVEL_1
    LOG_INFO("ntm_create failed");
#endif /* ifdef LOG_LEVEL_1 */

    ntu_destroy();
    neptune_destroy();
    return 0x90;
  }

  void *local = NTM_LOCAL(ntmem);
  MultiByteToWideChar(CP_UTF8, 0, dll_path, dll_path_len, local, wide_len);
  ((wchar_t *)local)[wide_len] = L'\0';

#endif /* ifdef __WIN32 */

  void *dll_path_addr = ntm_push(ntmem);
  if (dll_path_addr == NULL) {
#ifdef LOG_LEVEL_1
    LOG_INFO("ntm_push failed");
#endif /* ifdef LOG_LEVEL_1 */

    ntu_destroy();
    neptune_destroy();
    return 0x91;
  }

#ifdef LOG_LEVEL_1
  LOG_INFO("DLL Path Address(%p)", dll_path_addr);
#endif /* ifdef LOG_LEVEL_1 */

  void *load_library_ret = ntu_ucall(load_library_func, 1, dll_path_addr);

#ifdef LOG_LEVEL_1
  LOG_INFO("Return Value(%p)", load_library_ret);
#endif /* ifdef LOG_LEVEL_1 */

  ntm_delete(ntmem);

	ntu_destroy();
	neptune_destroy();
	return EXIT_SUCCESS;
}
