/*
 * Copyright (C) 2024, 2025 Sekran Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#include "ntutils.h"
#include "neptune.h"
#include "nmem.h"

#include "nerror.h"
#include "nthread.h"
#include "ntucc.h"

#include "ntmem.h"
#include "nttunnel.h"

#include <stdio.h>
#include <wchar.h>

struct ntutils_tfunctions {
#ifdef __WIN32
	void *fopen;
#endif /* ifdef __WIN32 */

	void *memset;
	void *malloc;
	void *fwrite;
  void *fflush;
	void *fclose;
	void *fread;
	void *free;
} ntu_funcs;

#ifdef __WIN32
DWORD ntu_tls_index;
#endif /* ifdef __WIN32 */

ntutils_t *_ntu_get(void)
{
#ifdef __WIN32
	return (ntutils_t *)TlsGetValue(ntu_tls_index);
#endif /* ifdef __WIN32 */
}

nerror_t ntu_set(ntutils_t *ntutils)
{
  ntutils_t *o_ntutils = ntu_get();
  if (o_ntutils != NULL && o_ntutils != ntutils)
    N_FREE(o_ntutils);

#ifdef __WIN32

	if (!TlsSetValue(ntu_tls_index, (void *)ntutils))
		return GET_ERR(NTUTILS_TLS_SET_VALUE_ERROR);

#endif /* ifdef __WIN32 */

	return N_OK;
}

ntutils_t *ntu_resize(size_t new_size)
{
  ntutils_t *ntutils;
  ntutils_t *o_ntutils = ntu_get();
  if (o_ntutils == NULL)
    ntutils = N_ALLOC(new_size);
  else
    ntutils = N_REALLOC(o_ntutils, new_size); 

  if (ntutils != NULL)
    ntu_set(ntutils);

  return ntutils;
}

#ifndef NTU_GLOBAL_CC

void _ntu_set_cc(ntucc_t cc) {
  ntutils_t *ntutils = ntu_get();
  if (ntutils != NULL)
    ntu_set_cc_ex(ntutils, cc);
}

ntutils_t *_ntu_o(ntucc_t cc) {
  ntutils_t *ntutils = ntu_get();
  if (ntutils != NULL)
    ntu_set_cc_ex(ntutils, cc);

  return ntutils;
}

#endif // !NTU_GLOBAL_CC

nerror_t ntu_global_init(void)
{
#ifdef __WIN32

	ntu_tls_index = TlsAlloc();
	if (ntu_tls_index == 0)
		return GET_ERR(NTUTILS_TLS_ALLOC_ERROR);

	HANDLE libc_module = GetModuleHandleA("ucrtbase");

#endif /* ifdef __WIN32 */

	if (libc_module == NULL) {

#ifdef LOG_LEVEL_1

	  libc_module = GetModuleHandleA("msvcrt");  
    LOG_ERROR("ntutils falling back to msvcrt");
    if (libc_module == NULL)
		  return GET_ERR(NTUTILS_ERROR_GET_LIBC);

#else /* ifndef LOG_LEVEL_1 */
		return GET_ERR(NTUTILS_ERROR_GET_LIBC);
#endif /* ifndef LOG_LEVEL_1 */
  }

#ifdef __WIN32
	char fun_names[] = "_wfopen\x05memsetmallocfwritefflushfclosefreadfree";
#endif /* ifdef __WIN32 */

	int8_t i = 8;
	int8_t pos = 0;
	int8_t c = 0;
	int8_t fun_pos = 0;

	char fun_name[i];

	while (true) {
		if (c == 0) {
			char fc = (char)fun_names[pos];
			if (fc == 0)
				break;

			if (fc <= 5) {
				c = fc;
				pos++;
			} else
				c = 1;

			i--;
			fun_name[i] = 0;
		}

		memcpy(fun_name, fun_names + pos, i);
		pos += i;
		c--;

		void *fun = GetProcAddress(libc_module, fun_name);
		if (fun == NULL)
			return GET_ERR(NTUTILS_FUNC_INIT_ERROR + fun_pos);

#ifdef LOG_LEVEL_3
		LOG_INFO("ntutils function(%s): %p", fun_name, fun);
#endif /* ifdef LOG_LEVEL_3 */

		((void **)&ntu_funcs)[fun_pos] = fun;
		fun_pos++;
	}

	return N_OK;
}

void ntu_global_destroy(void)
{
	if (ntu_tls_index != 0) {
#ifdef __WIN32
		TlsFree(ntu_tls_index);
#endif /* ifdef __WIN32 */

		ntu_tls_index = 0;
	}
}

nerror_t ntu_init(ntid_t thread_id, void *push_addr, void *sleep_addr)
{
	nerror_t ret;
	ntutils_t *ntutils = ntu_resize(sizeof(ntutils_t));

	RET_ERR(ntu_set(ntutils));
  ntu_set_cc_ex(ntutils, NTU_DEFAULT_CC);

  ntutils->nthread.thread = NULL;
	ret = nthread_init(&ntutils->nthread, thread_id, NTHREAD_BEST_PUSH_REG,
			   push_addr, sleep_addr);

	if (HAS_ERR(ret))
		goto ntu_init_error_exit;

  ret = ntt_init(NTU_NTTUNNEL_EX(ntutils));
  if (HAS_ERR(ret))
    goto ntu_init_error_exit;

  ntutils->ntmem = ntm_create();
  if (ntutils->ntmem == NULL) {
  ntu_init_error_exit:
		ntu_destroy();
		return ret;
  }

	return ret;
}

void ntu_destroy()
{
	ntutils_t *ntutils = ntu_get();
	if (ntutils == NULL)
		return;

	if (ntutils->nthread.thread != NULL) {
		if (ntutils->temp_path_addr != NULL)
			ntu_free(ntutils->temp_path_addr);
    
    ntt_destroy(NTU_NTTUNNEL_EX(ntutils));

    if (ntutils->ntmem != NULL)
      ntm_delete(ntutils->ntmem);

		nthread_destroy(&ntutils->nthread);
	}

	ntu_set(NULL);
}

nerror_t ntu_write_with_memset_ex(void *dest, const void *source, size_t length, const void *last_dest)
{
	size_t i = 0, j; 
	while (i < length) {
    if (last_dest != NULL) {
      while (((int8_t *)last_dest)[i] == ((int8_t *)source)[i]) {
        i++;
        if (i >= length)
          break;
      }
    }

		int8_t ms_value = ((int8_t *)source)[i];
		for (j = i + 1; j < length; j++) {
			if (((int8_t *)source)[j] != ms_value)
				break;
		}

		void *addr = ntu_memset(dest + i, ms_value, j - i);
		if (addr == NULL)
			return GET_ERR(NTUTILS_T_MEMSET_ERROR);

		i = j;
	}

	return N_OK;
}

nerror_t ntu_write_with_memset(void *dest, const void *source, size_t length)
{
  return ntu_write_with_memset_ex(dest, source, length, 0);
}

#ifdef NTUCC_WINDOWS_X64

static nthread_reg_offset_t winx64_regargs[] = {
	NTHREAD_RCX, NTHREAD_RDX, NTHREAD_R8, NTHREAD_R9
};

#endif /* ifdef NTUCC_WINDOWS_X64 */

static nerror_t ntu_set_args_v(ntutils_t *ntutils, uint8_t arg_count,
			       va_list args)
{
	void *regargs[NTUCC_MAX_REGARG_COUNT];

	int8_t sel_regarg_count = NTUCC_GET_REGARG_COUNT(ntutils->sel_cc);
	int8_t regarg_count;

	if (arg_count >= sel_regarg_count)
		regarg_count = sel_regarg_count;
	else
		regarg_count = arg_count;

	for (int8_t i = 0; i < regarg_count; i++)
		regargs[i] = va_arg(args, void *);

	uint8_t pusharg_count = arg_count - regarg_count;
	nthread_t *nthread = &ntutils->nthread;
	void *rsp = nthread_stack_begin(nthread);

	void *wpos;
	nthread_reg_offset_t *regargs_list;

#ifdef NTU_GLOBAL_CC

#ifdef LOG_LEVEL_3
	LOG_INFO("ntu_set_args_v(nthread_id=%ld, args=%d, args=%p)", NTHREAD_GET_ID(&ntutils->nthread), arg_count, args);
#endif /* ifdef LOG_LEVEL_3 */

  switch (NTU_GLOBAL_CC) {
    default:
  
#else /* ifndef NTU_GLOBAL_CC */

#ifdef LOG_LEVEL_3
	LOG_INFO("ntu_set_args_v(cc=%04X, nthread_id=%ld, args=%d, args=%p)", ntutils->sel_cc, NTHREAD_GET_ID(&ntutils->nthread), arg_count, args);
#endif /* ifdef LOG_LEVEL_3 */

  switch (ntutils->sel_cc) {
    default:
		  return GET_ERR(NTUTILS_UNKNOWN_CC_ERROR);

#endif /* ifndef NTU_GLOBAL_CC */

#ifdef NTUCC_WINDOWS_X64

    case NTUCC_WINDOWS_X64:
		  regargs_list = winx64_regargs;
    ntu_sel_cc_winx64:
      wpos = rsp + sizeof(void *) * 4;
      break;

#endif /* ifdef NTUCC_WINDOWS_X64 */


#ifdef NTUCC_WINDOWS_X64_PASS_RCX
    
    case NTUCC_WINDOWS_X64_PASS_RCX:
      regargs_list = winx64_regargs + 1;
      goto ntu_sel_cc_winx64;

#endif /* ifdef NTUCC_WINDOWS_X64_PASS_RCX */

  }

	for (uint8_t i = 0; i < pusharg_count; i++) {
		void *arg = va_arg(args, void *);
		RET_ERR(ntu_write_with_memset(wpos, arg, sizeof(arg)));

		wpos += sizeof(void *);
	}

	for (int8_t i = 0; i < regarg_count; i++)
		NTHREAD_SET_REG(nthread, regargs_list[i], regargs[i]);

	return N_OK;
}

nerror_t ntu_call_v(ntutils_t *ntutils, void *func_addr, uint8_t arg_count,
		    va_list args)
{
	RET_ERR(ntu_set_args_v(ntutils, arg_count, args));
	return nthread_call(&ntutils->nthread, func_addr, &ntutils->ret_value);
}

nerror_t ntu_call(ntutils_t *ntutils, void *func_addr, uint8_t arg_count, ...)
{
	va_list args;
	va_start(args, arg_count);

	nerror_t ret = ntu_call_v(ntutils, func_addr, arg_count, args);

	va_end(args);
	return ret;
}

void *ntu_ucall_v(void *func_addr, uint8_t arg_count, va_list args)
{
	ntutils_t *ntutils = ntu_get();
	if (HAS_ERR(ntu_call_v(ntutils, func_addr, arg_count, args)))
		return NULL;

	return ntutils->ret_value;
}

void *ntu_ucall(void *func_addr, uint8_t arg_count, ...)
{
	va_list args;
	va_start(args, arg_count);

	nerror_t *ret = ntu_ucall_v(func_addr, arg_count, args);

	va_end(args);
	return ret;
}

void *ntu_memset(void *dest, int fill, size_t length)
{
  ntu_set_cc(NTU_DEFAULT_CC);
	return ntu_ucall(ntu_funcs.memset, 3, dest, fill, length);
}

void *ntu_malloc(size_t size)
{
  ntu_set_cc(NTU_DEFAULT_CC);
	return ntu_ucall(ntu_funcs.malloc, 1, size);
}

void ntu_free(void *address)
{
  ntu_set_cc(NTU_DEFAULT_CC);
	ntu_ucall(ntu_funcs.free, 1, address);
}

FILE *ntu_fopen(const wchar_t *filename, const wchar_t *mode)
{
  ntu_set_cc(NTU_DEFAULT_CC);
	return (FILE *)ntu_ucall(ntu_funcs.fopen, 2, filename, mode);
}

size_t ntu_fread(void *buffer, size_t size, size_t count, FILE *fstream)
{
  ntu_set_cc(NTU_DEFAULT_CC);
	return (size_t)ntu_ucall(ntu_funcs.fread, 4, buffer, size, count,
				 fstream);
}

size_t ntu_fwrite(const void *buffer, size_t size, size_t count, FILE *fstream)
{
  ntu_set_cc(NTU_DEFAULT_CC);
	return (size_t)ntu_ucall(ntu_funcs.fwrite, 4, buffer, size, count,
				 fstream);
}

int ntu_fflush(FILE *fstream)
{
	ntutils_t *ntutils = ntu_o(NTU_DEFAULT_CC);
	if (HAS_ERR(ntu_call(ntutils, ntu_funcs.fflush, 1, fstream)))
		return -1;

	return (size_t)ntutils->ret_value;
}

int ntu_fclose(FILE *fstream)
{
	ntutils_t *ntutils = ntu_o(NTU_DEFAULT_CC);
	if (HAS_ERR(ntu_call(ntutils, ntu_funcs.fclose, 1, fstream)))
		return -1;

	return (size_t)ntutils->ret_value;
}

static void *
ntu_alloc_str_ex(const char *str, size_t alloc_len, size_t str_len)
{
  if (str_len > alloc_len)
    return NULL;

  void *addr = ntu_malloc(alloc_len);
	if (addr == NULL)
		return NULL;

	if (HAS_ERR(ntu_write(addr, str, str_len))) {
		ntu_free(addr);
		return NULL;
	}

	return addr;
}

void *
ntu_alloc_nstr(const char *str, size_t len)
{
	size_t str_len = (strlen(str) + 1) * sizeof(*str);
  return ntu_alloc_str_ex(str, len, str_len);
}

void *
ntu_alloc_str(const char *str)
{
	size_t str_len = (strlen(str) + 1) * sizeof(*str);
  return ntu_alloc_str_ex(str, str_len, str_len);
}

ntmem_t *ntu_ntmem() {
  ntutils_t *ntutils = ntu_get();
  return NTU_NTMEM_EX(ntutils);
}

void *ntu_rmem() {
  ntmem_t *ntmem = ntu_ntmem();
  return NTM_REMOTE(ntmem);
}

void *ntu_mem() {
  ntmem_t *ntmem = ntu_ntmem();
  return NTM_LOCAL(ntmem);
}

void *ntu_mem_pull() {
  ntmem_t *ntmem = ntu_ntmem();
  nttunnel_t *nttunnel = ntu_nttunnel();

  return ntm_pull_with_tunnel(ntmem, nttunnel);
}

void *ntu_mem_push()
{
  ntmem_t *ntmem = ntu_ntmem();
  nttunnel_t *nttunnel = ntu_nttunnel();

  return ntm_push(ntmem, nttunnel);
}

nttunnel_t *ntu_nttunnel()
{
  ntutils_t *ntutils = ntu_get();
  return NTU_NTTUNNEL_EX(ntutils);
}

bool ntu_can_read()
{
  nttunnel_t *nttunnel = ntu_nttunnel();
  return ntt_can_read(nttunnel);
}

bool ntu_can_write()
{
  nttunnel_t *nttunnel = ntu_nttunnel();
  return ntt_can_write(nttunnel);
}

nerror_t ntu_tunnel_read(const void *dest, void *source, size_t length)
{
  nttunnel_t *tunnel = ntu_nttunnel();
  return ntt_read(tunnel, dest, source, length);
}

nerror_t ntu_tunnel_write(void *dest, const void *source, size_t length)
{
  nttunnel_t *tunnel = ntu_nttunnel();
  return ntt_write(tunnel, dest, source, length);
}


