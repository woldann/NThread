/*
 * Copyright (C) 2024, 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#ifndef __NTUTILS_H__
#define __NTUTILS_H__

#include "nerror.h"
#include "nthread.h"
#include "ntucc.h"
#include "nmutex.h"

#ifdef __WIN32
#define NTU_DEFAULT_CC NTUCC_WINDOWS_X64
#define NTU_DEFAULT_PFA_CC NTUCC_WINDOWS_X64_PASS_RCX
#define NTU_DEFAULT_CC_FA NTHREAD_RCX
#else // !__WIN32
#define NTU_DEFAULT_CC NTUCC_CDECL
#define NTU_DEFAULT_PFA_CC NTUCC_CDECL_PASS_
#define NTU_DEFAULT_CC_FA NTHREAD_RCX
#endif // !__WIN32

#define NTUTILS_ERROR 0x7340

#define NTUTILS_ERROR_GET_LIBC 0x7341
#define NTUTILS_GET_TEMP_PATH_ERROR 0x7342
#define NTUTILS_GET_TEMP_FILE_ERROR 0x7343
#define NTUTILS_UNKNOWN_CC_ERROR 0x7344
#define NTUTILS_ALLOC_ERROR 0x7345
#define NTUTILS_TLS_SET_VALUE_ERROR 0x7346
#define NTUTILS_TLS_ALLOC_ERROR 0x7347
#define NTUTILS_T_MALLOC_ERROR 0x7348
#define NTUTILS_T_MEMSET_ERROR 0x7349
#define NTMEM_CREATE_ERROR 0x734A
#define NTTUNNEL_CREATE_ERROR 0x734B

#define NTUTILS_FOPEN_R_ERROR 0x734B
#define NTUTILS_T_FOPEN_R_ERROR 0x734C
#define NTUTILS_FOPEN_W_ERROR 0x734D
#define NTUTILS_T_FOPEN_W_ERROR 0x734E

#define NTUTILS_FREAD_ERROR 0x734F
#define NTUTILS_T_FREAD_ERROR 0x7350
#define NTUTILS_FWRITE_ERROR 0x7351
#define NTUTILS_T_FWRITE_ERROR 0x7352

#define NTUTILS_FUNC_INIT_ERROR 0x7353
#define NTUTILS_FUNC_INIT_ERROR_E (NTUTILS_FUNC_INIT_ERROR + 7)

#define NTUTILS_ERROR_E NTUTILS_FUNC_INIT_ERROR_E

#include "nttunnel.h"

typedef struct ntmem ntmem_t;

#ifdef __WIN32
#define NTU_GLOBAL_CC NTU_DEFAULT_CC
#endif // __WIN32

struct ntutils {
	void *ret_value;
	ntucc_t sel_cc;

  nttunnel_t nttunnel;
  ntmem_t *ntmem; 

#ifdef __WIN32

	DWORD temp_path_len;
	void *temp_path_addr;

#endif /* ifdef __WIN32 */

	nthread_t nthread;
};

typedef struct ntutils ntutils_t;

ntutils_t *_ntu_get(void);
nerror_t ntu_set(ntutils_t *ntutils);

#define ntu_get() _ntu_get()

#define ntu_set_cc_ex(ntutils, cc) (ntutils->sel_cc = cc)

#ifndef NTU_GLOBAL_CC

void _ntu_set_cc(ntucc_t cc);

#define ntu_set_cc(cc) _ntu_set_cc(cc)

ntutils_t *_ntu_o(ntucc_t cc);

#define ntu_o(cc) _ntu_o(cc)

#else // NTU_GLOBAL_CC

#define ntu_set_cc(cc) do {} while(0)
#define ntu_o(cc) ntu_get()

#endif // NTU_GLOBAL_CC

nerror_t ntu_global_init(void);

void ntu_global_destroy(void);

nerror_t ntu_init(ntid_t thread_id, void *push_addr, void *sleep_addr);

void ntu_destroy();

nerror_t ntu_call_v(ntutils_t *ntutils, void *func_addr, uint8_t arg_count,
		    va_list args);

nerror_t ntu_call(ntutils_t *ntutils, void *function_address, uint8_t arg_count,
		  ...);

void *ntu_ucall_v(void *func_addr, uint8_t arg_count, va_list args);

void *ntu_ucall(void *func_addr, uint8_t arg_count, ...);

void *ntu_memset(void *dest, int fill, size_t length);

void *ntu_malloc(size_t size);

void ntu_free(void *address);

FILE *ntu_fopen(const wchar_t *filename, const wchar_t *mode);

size_t ntu_fread(void *buffer, size_t size, size_t count, FILE *fstream);

size_t ntu_fwrite(const void *buffer, size_t size, size_t count, FILE *fstream);

int ntu_fflush(FILE *fstream);

int ntu_fclose(FILE *fstream);

void *ntu_alloc_str(const char *str);

nerror_t ntu_write_with_memset_ex(void *dest, const void *source, size_t length, const void *last_dest);

nerror_t ntu_write_with_memset(void *dest, const void *source, size_t length);

nerror_t ntu_read_memory(const void *dest, void *source, size_t length);

nerror_t ntu_write_memory(void *dest, const void *source, size_t length);

#define NTU_NTMEM_EX(ntutils) (ntutils->ntmem)
#define NTU_NTMEM() (ntu_ntmem())

ntmem_t *ntu_ntmem();

void *ntu_rmem();

void *ntu_mem();

void *ntu_mem_pull();

void *ntu_mem_push_memset();

void *ntu_mem_push();

#define NTU_NTTUNNEL_EX(ntutils) (&ntutils->nttunnel)
#define NTU_NTTUNNEL() (ntu_nttunnel())

nttunnel_t *ntu_nttunnel();

bool ntu_can_read();

bool ntu_can_write();

nerror_t ntu_tunnel_read(const void *dest, void *source, size_t length);

nerror_t ntu_tunnel_write(void *dest, const void *source, size_t length);

#define ntu_read(...) ntu_tunnel_read(__VA_ARGS__)
#define ntu_write(...) ntu_tunnel_write(__VA_ARGS__)

#define ntu_read_memory(...) ntu_tunnel_read(__VA_ARGS__)
#define ntu_write_memory(...) ntu_tunnel_write(__VA_ARGS__)

#endif // !__NTUTILS_H__
