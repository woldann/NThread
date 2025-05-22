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

void _ntu_set_cc(ntucc_t cc)
{
	ntutils_t *ntutils = ntu_get();
	if (ntutils != NULL)
		ntu_set_cc_ex(ntutils, cc);
}

void _ntu_set_default_cc()
{
	_ntu_set_cc(NTU_DEFAULT_CC);
}

ntutils_t *_ntu_o(ntucc_t cc)
{
	ntutils_t *ntutils = ntu_get();
	if (ntutils != NULL)
		ntu_set_cc_ex(ntutils, cc);

	return ntutils;
}

#endif // !NTU_GLOBAL_CC

void *ntu_get_libc_base()
{
  void *ret;

#ifdef __WIN32

	ret = (void *)GetModuleHandleA("msvcrt");
  if (ret == NULL) {

#ifdef LOG_LEVEL_1
    LOG_INFO("msvcrt.dll not found, loading dynamically...");
#endif /* ifdef LOG_LEVEL_1 */

    LoadLibraryA("msvcrt");
	  ret = (void *)GetModuleHandleA("msvcrt");
  }

#endif /* ifdef __WIN32 */

	return ret;
}

nerror_t ntu_global_init(void)
{
#ifdef __WIN32

	ntu_tls_index = TlsAlloc();
	if (ntu_tls_index == 0)
		return GET_ERR(NTUTILS_TLS_ALLOC_ERROR);

#endif /* ifdef __WIN32 */

	void *libc_base = ntu_get_libc_base();
	if (libc_base == NULL)
		return GET_ERR(NTUTILS_GET_LIBC_BASE_ERROR);

#ifdef __WIN32
	char func_names[] =
		"_wfopen\x05memsetmallocfwritefflushfclosefreadfree";
#endif /* ifdef __WIN32 */

	int8_t i = 8;
	int8_t pos = 0;
	int8_t c = 0;
	int8_t func_pos = 0;

	char func_name[i];

	while (true) {
		if (c == 0) {
			char fc = (char)func_names[pos];
			if (fc == 0)
				break;

			if (fc <= 5) {
				c = fc;
				pos++;
			} else
				c = 1;

			i--;
			func_name[i] = 0;
		}

		memcpy(func_name, func_names + pos, i);
		pos += i;
		c--;

#ifdef __WIN32
		void *func = GetProcAddress((void *)libc_base, func_name);
#endif /* ifdef __WIN32 */

		if (func == NULL)
			return GET_ERR(NTUTILS_FUNC_INIT_ERROR + func_pos);

#ifdef LOG_LEVEL_3
		LOG_INFO("ntutils function(%s): %p", func_name, func);
#endif /* ifdef LOG_LEVEL_3 */

		((void **)&ntu_funcs)[func_pos] = func;
		func_pos++;
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

nerror_t ntu_init_ex(ntid_t thread_id, nthread_reg_offset_t push_reg_offset,
		     void *push_addr, void *sleep_addr)
{
	nerror_t ret;
	ntutils_t *ntutils = ntu_resize(sizeof(ntutils_t));

	RET_ERR(ntu_set(ntutils));
	ntu_set_default_cc();

  ntutils->stack_helper = NULL;
	ntutils->nthread.thread = NULL;

	ret = nthread_init(&ntutils->nthread, thread_id, push_reg_offset,
			   push_addr, sleep_addr);

	if (HAS_ERR(ret))
		goto ntu_init_error_exit;

  ntutils->stack_helper = ntm_create_ex(255 * sizeof(void*));
  if (ntutils->stack_helper == NULL) {
    ret = GET_ERR(NTUTILS_NTM_CREATE_EX_ERROR);
    goto ntu_init_error_exit;
  }

	ret = ntt_init(NTU_NTTUNNEL_EX(ntutils));
	if (HAS_ERR(ret)) {
ntu_init_error_exit:
		ntu_destroy();
  }

	return ret;
}

nerror_t ntu_init(ntid_t thread_id, void *push_addr, void *sleep_addr)
{
	return ntu_init_ex(thread_id, NTHREAD_BEST_PUSH_REG, push_addr,
			   sleep_addr);
}

void ntu_destroy()
{
	ntutils_t *ntutils = ntu_get();
	if (ntutils == NULL)
		return;

	if (ntutils->nthread.thread != NULL) {
		ntt_destroy(NTU_NTTUNNEL_EX(ntutils));

    if(ntutils->stack_helper != NULL)
      ntm_delete(ntutils->stack_helper);

		nthread_destroy(&ntutils->nthread);
	}

	ntu_set(NULL);
}

nerror_t ntu_write_with_memset_value(void *dest, const void *source,
				     size_t length, int8_t last_value)
{
	size_t i = 0, j;
	while (i < length) {
		while (last_value == ((int8_t *)source)[i]) {
			i++;
			if (i >= length)
				break;
		}

		int8_t ms_value = ((int8_t *)source)[i];
		for (j = i + 1; j < length; j++) {
			if (((int8_t *)source)[j] != ms_value)
				break;
		}

		void *addr = ntu_memset(dest + i, ms_value, j - i);
		if (addr == NULL)
			return GET_ERR(NTUTILS_NTU_MEMSET_ERROR);

		i = j;
	}

	return N_OK;
}

nerror_t ntu_write_with_memset_dest(void *dest, const void *source,
				    size_t length, const void *last_dest)
{
	size_t i = 0, j;
	while (i < length) {
		if (last_dest != NULL) {
			while (((int8_t *)last_dest)[i] ==
			       ((int8_t *)source)[i]) {
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
			return GET_ERR(NTUTILS_NTU_MEMSET_ERROR);

		i = j;
	}

	return N_OK;
}

nerror_t ntu_write_with_memset(void *dest, const void *source, size_t length)
{
	size_t i = 0, j;
	while (i < length) {
		int8_t ms_value = ((int8_t *)source)[i];
		for (j = i + 1; j < length; j++) {
			if (((int8_t *)source)[j] != ms_value)
				break;
		}

		void *addr = ntu_memset(dest + i, ms_value, j - i);
		if (addr == NULL)
			return GET_ERR(NTUTILS_NTU_MEMSET_ERROR);

		i = j;
	}

	return N_OK;
}

void ntu_set_reg_args(ntutils_t *ntutils, uint8_t arg_count, void **args)
{
	nthread_t *nthread = &ntutils->nthread;

#ifdef NTU_GLOBAL_CC
	ntucc_t sel_cc = NTU_GLOBAL_CC;
#else /* ifdnef NTU_GLOBAL_CC */
	ntucc_t sel_cc = ntutils->sel_cc;
#endif /* ifndef NTU_GLOBAL_CC */

	for (int8_t i = 0; i < 8 && i < arg_count; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
		if (reg_index == 0)
			continue;

		nthread_reg_offset_t off =
			NTHREAD_REG_INDEX_TO_OFFSET(reg_index);

		NTHREAD_SET_REG(nthread, off, args[i]);
	}
}

nerror_t ntu_set_args_v(ntutils_t *ntutils, uint8_t arg_count, va_list args)
{
	nthread_t *nthread = &ntutils->nthread;

#ifdef NTU_GLOBAL_CC
	ntucc_t sel_cc = NTU_GLOBAL_CC;
#else /* ifdnef NTU_GLOBAL_CC */
	ntucc_t sel_cc = ntutils->sel_cc;
#endif /* ifndef NTU_GLOBAL_CC */

#ifdef LOG_LEVEL_3
	LOG_INFO("ntu_set_args_v(cc=%p, nthread_id=%ld, arg_count=%d, args=%p)",
		 sel_cc, NTHREAD_GET_ID(nthread), arg_count, args);
#endif /* ifdef LOG_LEVEL_3 */

  int8_t reg_arg_count = 0;
  for (int8_t i = 0; i < 8; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
    if (reg_index != 0)
      reg_arg_count++;
  }

  if (reg_arg_count > arg_count)
    reg_arg_count = arg_count;

  uint8_t push_arg_count = arg_count - reg_arg_count;
  bool need_push = push_arg_count > 0;
 
	void *rsp = nthread_stack_begin(nthread);
	void *wpos = rsp + NTUCC_GET_STACK_ADD(sel_cc);

  void **push_args;
  ntmem_t *ntmem;
  if (need_push) {
    LOG_INFO("push_arg_count=%d %p", push_arg_count, rsp);
    ntmem = ntutils->stack_helper;
    NTM_SET_REMOTE(ntmem, wpos);

    if (ntm_reset_remote_ex(ntmem, push_arg_count * sizeof(void *)) == NULL)
      return GET_ERR(NTUTILS_NTM_RESET_REMOTE_EX_ERROR);

    push_args = (void **) ntm_reset_locals(ntmem);
  }
	uint8_t push_arg_pos;

	void *reg_args[8];
	nthread_reg_offset_t reg_offsets[8];

  bool reverse = (sel_cc & NTUCC_REVERSE_OP) != 0;
  if (reverse)
    push_arg_pos = push_arg_count - 1;
  else
    push_arg_pos = 0;

	for (uint8_t i = 0; i < arg_count; i++) {
		void *arg = va_arg(args, void *);
		if (i < 8) {
			int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
			if (reg_index != 0) {
				reg_args[i] = arg;
				continue;
			}
		}

    push_args[push_arg_pos] = arg;
    if (reverse)
      push_arg_pos--;
    else
      push_arg_pos++;
  }

  if (need_push && ntm_push(ntmem) == NULL)
    return GET_ERR(NTUTILS_NTM_PUSH_ERROR);

	ntu_set_reg_args(ntutils, arg_count, reg_args);
	return N_OK;
}

nerror_t ntu_set_args(ntutils_t *ntutils, uint8_t arg_count, ...)
{
	va_list args;
	va_start(args, arg_count);

	nerror_t ret = ntu_set_args_v(ntutils, arg_count, args);

	va_end(args);
	return ret;
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

void *_ntu_ucall(void *func_addr, uint8_t arg_count, ...)
{
	va_list args;
	va_start(args, arg_count);

	nerror_t *ret = ntu_ucall_v(func_addr, arg_count, args);

	va_end(args);
	return ret;
}

void *ntu_memset(void *dest, int fill, size_t length)
{
	ntu_set_default_cc();
	return ntu_ucall(ntu_funcs.memset, dest, fill, length);
}

void *ntu_malloc(size_t size)
{
	ntu_set_default_cc();
	return ntu_ucall(ntu_funcs.malloc, size);
}

void ntu_free(void *address)
{
	ntu_set_default_cc();
	ntu_ucall(ntu_funcs.free, address);
}

FILE *ntu_fopen(const nfile_path_t filename, const nfile_path_t mode)
{
	ntu_set_default_cc();
	return (FILE *)ntu_ucall(ntu_funcs.fopen, filename, mode);
}

size_t ntu_fread(void *buffer, size_t size, size_t count, FILE *fstream)
{
	ntu_set_default_cc();
	return (size_t)ntu_ucall(ntu_funcs.fread, buffer, size, count, fstream);
}

size_t ntu_fwrite(const void *buffer, size_t size, size_t count, FILE *fstream)
{
	ntu_set_default_cc();
	return (size_t)ntu_ucall(ntu_funcs.fwrite, buffer, size, count,
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

void *ntu_alloc_str(const char *str)
{
	size_t str_len = (strlen(str) + 1) * sizeof(*str);
	void *addr = ntu_malloc(str_len);
	if (addr == NULL)
		return NULL;

	if (HAS_ERR(ntu_write(addr, str, str_len))) {
		ntu_free(addr);
		return NULL;
	}

	return addr;
}

nttunnel_t *ntu_nttunnel()
{
	ntutils_t *ntutils = ntu_get();
	return NTU_NTTUNNEL_EX(ntutils);
}

bool ntu_tunnel_can_read()
{
	nttunnel_t *nttunnel = ntu_nttunnel();
	return ntt_can_read(nttunnel);
}

bool ntu_tunnel_can_write()
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
