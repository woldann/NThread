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
#ifdef _WIN32
	void *fopen;
#endif /* ifdef _WIN32 */

	void *memset;
	void *malloc;
	void *fwrite;
	void *fflush;
	void *fclose;
	void *fread;
	void *free;
} ntu_funcs;

#ifdef _WIN32

#ifdef NTU_USE_TLS
DWORD ntu_tls_index = 0;
#else /* ifndef NTU_USE_TLS */
ntutils_t *ntu_ntutils = NULL;
#endif /* ifndef NTU_USE_TLS */

#endif /* ifdef _WIN32 */

NTHREAD_API ntutils_t *_ntu_get(void)
{
#ifdef _WIN32
#ifdef NTU_USE_TLS
	return (ntutils_t *)TlsGetValue(ntu_tls_index);
#else /* ifndef NTU_USE_TLS */
	return ntu_ntutils;
#endif /* ifndef NTU_USE_TLS */
#endif /* ifdef _WIN32 */

	return NULL;
}

NTHREAD_API nerror_t ntu_set(ntutils_t *ntutils)
{
#ifdef _WIN32
#ifdef NTU_USE_TLS

	if (!TlsSetValue(ntu_tls_index, (void *)ntutils))
		return GET_ERR(NTUTILS_TLS_SET_VALUE_ERROR);

#else /* ifndef NTU_USE_TLS */

	ntu_ntutils = ntutils;

#endif /* ifndef NTU_USE_TLS */
#endif /* ifdef _WIN32 */

	return N_OK;
}

NTHREAD_API nerror_t ntu_resize(size_t new_size)
{
	ntutils_t *o_ntutils = ntu_get();
	if (new_size == 0) {
		if (o_ntutils != NULL)
			N_FREE(o_ntutils);

		ntu_set(NULL);
	} else {
		ntutils_t *ntutils;
		if (o_ntutils == NULL)
			ntutils = N_ALLOC(new_size);
		else
			ntutils = N_REALLOC(o_ntutils, new_size);

		if (ntutils == NULL)
			return GET_ERR(NTUTILS_ALLOC_ERROR);

		ntu_set(ntutils);
	}

	return N_OK;
}

#ifndef NTU_GLOBAL_CC

NTHREAD_API void _ntu_set_cc(ntucc_t cc)
{
	ntutils_t *ntutils = ntu_get();
	if (ntutils != NULL)
		ntu_set_cc_ex(ntutils, cc);
}

NTHREAD_API void _ntu_set_default_cc()
{
	_ntu_set_cc(NTU_DEFAULT_CC);
}

NTHREAD_API ntutils_t *_ntu_o(ntucc_t cc)
{
	ntutils_t *ntutils = ntu_get();
	if (ntutils != NULL)
		ntu_set_cc_ex(ntutils, cc);

	return ntutils;
}

#endif // !NTU_GLOBAL_CC

NTHREAD_API void *ntu_get_libc_base()
{
	void *ret;

#ifdef _WIN32

	ret = (void *)GetModuleHandleA("msvcrt");
	if (ret == NULL) {
#ifdef LOG_LEVEL_1
		LOG_INFO("msvcrt.dll not found, loading dynamically...");
#endif /* ifdef LOG_LEVEL_1 */

		LoadLibraryA("msvcrt");
		ret = (void *)GetModuleHandleA("msvcrt");
	}

#endif /* ifdef _WIN32 */

	return ret;
}

NTHREAD_API nerror_t ntu_global_init(void)
{
#ifdef _WIN32
#ifdef NTU_USE_TLS

	ntu_tls_index = TlsAlloc();
	if (ntu_tls_index == 0)
		return GET_ERR(NTUTILS_TLS_ALLOC_ERROR);

#endif /* ifdef NTU_USE_TLS */
#endif /* ifdef _WIN32 */

	void *libc_base = ntu_get_libc_base();
	if (libc_base == NULL)
		return GET_ERR(NTUTILS_GET_LIBC_BASE_ERROR);

#ifdef _WIN32

	const char func_names[8][8] = { "_wfopen", "memset", "malloc", "fwrite",
					"fflush",  "fclose", "fread",  "free" };

#endif /* ifdef _WIN32 */

	int8_t i;
	for (i = 0; i < 8; i++) {
		const char *func_name = func_names[i];

#ifdef _WIN32
		void *func = GetProcAddress((void *)libc_base, func_name);
#endif /* ifdef _WIN32 */

		if (func == NULL)
			return GET_ERR(NTUTILS_FUNC_INIT_ERROR + i);

#ifdef LOG_LEVEL_3
		LOG_INFO("ntutils function(%s): %p", func_name, func);
#endif /* ifdef LOG_LEVEL_3 */

		((void **)&ntu_funcs)[i] = func;
	}

	return N_OK;
}

NTHREAD_API void ntu_global_destroy(void)
{
	ntu_resize(0);

#ifdef _WIN32
#ifdef NTU_USE_TLS

	if (ntu_tls_index != 0) {
		TlsFree(ntu_tls_index);

		ntu_tls_index = 0;
	}

#endif /* ifdef NTU_USE_TLS */
#endif /* ifdef _WIN32 */
}

NTHREAD_API nerror_t ntu_upgrade(nthread_t *nthread)
{
	if (!NTHREAD_IS_VALID(nthread))
		return GET_ERR(NTUTILS_NTHREAD_ERROR);

	if (HAS_ERR(ntu_resize(sizeof(ntutils_t))))
		return GET_ERR(NTUTILS_NTU_RESIZE_ERROR);

	ntutils_t *ntutils = ntu_get();
	if (ntutils == NULL)
		return GET_ERR(NTUTILS_NTU_GET_ERROR);

	memcpy(&ntutils->nthread, nthread, sizeof(nthread_t));
	nttunnel_t *nttunnel = NTU_NTTUNNEL_EX(ntutils);

	memset(nttunnel, 0, sizeof(nttunnel_t));
	if (HAS_ERR(ntt_init(nttunnel))) {
		ntu_destroy();
		return GET_ERR(NTUTILS_NTT_INIT_ERROR);
	}

	return N_OK;
}

NTHREAD_API nerror_t ntu_attach_ex(ntid_t thread_id,
				   nthread_reg_offset_t push_reg_offset,
				   void *push_addr, void *sleep_addr)
{
	nthread_t nthread;
	if (HAS_ERR(nthread_init(&nthread, thread_id, push_reg_offset,
				 push_addr, sleep_addr))) {
		return GET_ERR(NTUTILS_NTHREAD_INIT_ERROR);
	}

	return ntu_upgrade(&nthread);
}

NTHREAD_API nerror_t ntu_attach(ntid_t thread_id, void *push_addr,
				void *sleep_addr)
{
	return ntu_attach_ex(thread_id, NTHREAD_BEST_PUSH_REG, push_addr,
			     sleep_addr);
}

NTHREAD_API void ntu_destroy()
{
	ntutils_t *ntutils = ntu_get();
	if (ntutils == NULL)
		return;

	if (NTHREAD_IS_VALID(&ntutils->nthread)) {
		ntt_destroy(NTU_NTTUNNEL_EX(ntutils));
		nthread_destroy(&ntutils->nthread);
	}

	ntu_resize(0);
}

NTHREAD_API nerror_t ntu_write_with_memset_value(void *dest, const void *source,
						 size_t length,
						 int8_t last_value)
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

		void *addr = ntu_memset((void *)((int8_t *)dest + i), ms_value,
					j - i);
		if (addr == NULL)
			return GET_ERR(NTUTILS_NTU_MEMSET_ERROR);

		i = j;
	}

	return N_OK;
}

NTHREAD_API nerror_t ntu_write_with_memset_dest(void *dest, const void *source,
						size_t length,
						const void *last_dest)
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

		void *addr = ntu_memset((void *)((int8_t *)dest + i), ms_value,
					j - i);
		if (addr == NULL)
			return GET_ERR(NTUTILS_NTU_MEMSET_ERROR);

		i = j;
	}

	return N_OK;
}

NTHREAD_API nerror_t ntu_write_with_memset(void *dest, const void *source,
					   size_t length)
{
	size_t i = 0, j;
	while (i < length) {
		int8_t ms_value = ((int8_t *)source)[i];
		for (j = i + 1; j < length; j++) {
			if (((int8_t *)source)[j] != ms_value)
				break;
		}

		void *addr = ntu_memset((void *)((int8_t *)dest + i), ms_value,
					j - i);
		if (addr == NULL)
			return GET_ERR(NTUTILS_NTU_MEMSET_ERROR);

		i = j;
	}

	return N_OK;
}

NTHREAD_API void ntu_set_reg_args_ex(uint8_t arg_count, void **args,
				     ntucc_t sel_cc)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	int8_t i;
	for (i = 0; i < 8 && i < arg_count; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
		if (reg_index == 0)
			continue;

		nthread_reg_offset_t off =
			NTHREAD_REG_INDEX_TO_OFFSET(reg_index);

		NTHREAD_SET_REG(nthread, off, args[i]);
	}
}

NTHREAD_API void ntu_set_reg_args(uint8_t arg_count, void **args)
{
#ifdef NTU_GLOBAL_CC
	ntucc_t sel_cc = NTU_GLOBAL_CC;
#else /* ifdnef NTU_GLOBAL_CC */

	ntutils_t *ntutils = ntu_get();
	ntucc_t sel_cc = ntutils->sel_cc;

#endif /* ifndef NTU_GLOBAL_CC */

	ntu_set_reg_args_ex(arg_count, args, sel_cc);
}

NTHREAD_API nerror_t ntu_set_args_v(uint8_t arg_count, va_list args)
{
	ntutils_t *ntutils = ntu_get();
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

	uint8_t i;
	for (i = 0; i < 8; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
		if (reg_index != 0)
			reg_arg_count++;
	}

	if (reg_arg_count > arg_count)
		reg_arg_count = arg_count;

	uint8_t push_arg_count = arg_count - reg_arg_count;
	bool need_push = push_arg_count > 0;

	void *rsp = nthread_stack_begin(nthread);
	void *wpos = (void *)((int8_t *)rsp + NTUCC_GET_STACK_ADD(sel_cc));

	size_t push_args_size;
	void **push_args;
	if (need_push) {
		push_args_size = push_arg_count * sizeof(void *);
		push_args = (void **)ntutils->stack_helper;
	}

	uint8_t push_arg_pos;

	void *reg_args[8];
	bool reverse = (sel_cc & NTUCC_REVERSE_OP) != 0;
	if (reverse)
		push_arg_pos = push_arg_count - 1;
	else
		push_arg_pos = 0;

	for (i = 0; i < arg_count; i++) {
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

	if (need_push) {
		if (HAS_ERR(ntu_write_memory(wpos, push_args, push_args_size)))
			return GET_ERR(NTUTILS_WRITE_MEMORY_ERROR);
	}

	ntu_set_reg_args_ex(arg_count, reg_args, sel_cc);
	return N_OK;
}

NTHREAD_API nerror_t ntu_set_args(int arg_count, ...)
{
	va_list args;
	va_start(args, arg_count);

	nerror_t ret = ntu_set_args_v(arg_count, args);

	va_end(args);
	return ret;
}

NTHREAD_API void ntu_get_reg_args_ex(uint8_t arg_count, void **args,
				     ntucc_t sel_cc)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	int8_t i;
	for (i = 0; i < 8 && i < arg_count; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
		if (reg_index == 0)
			continue;

		nthread_reg_offset_t off =
			NTHREAD_REG_INDEX_TO_OFFSET(reg_index);

		args[i] = NTHREAD_GET_OREG(nthread, off);
	}
}

NTHREAD_API void ntu_get_reg_args(uint8_t arg_count, void **args)
{
#ifdef NTU_GLOBAL_CC
	ntucc_t sel_cc = NTU_GLOBAL_CC;
#else /* ifdnef NTU_GLOBAL_CC */

	ntutils_t *ntutils = ntu_get();
	ntucc_t sel_cc = ntutils->sel_cc;

#endif /* ifndef NTU_GLOBAL_CC */

	ntu_get_reg_args_ex(arg_count, args, sel_cc);
}

NTHREAD_API nerror_t ntu_get_args(uint8_t arg_count, void **args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	RET_ERR(nthread_get_regs(nthread));

#ifdef NTU_GLOBAL_CC
	ntucc_t sel_cc = NTU_GLOBAL_CC;
#else /* ifdnef NTU_GLOBAL_CC */
	ntucc_t sel_cc = ntutils->sel_cc;
#endif /* ifndef NTU_GLOBAL_CC */

#ifdef LOG_LEVEL_3
	LOG_INFO("ntu_get_args(cc=%p, nthread_id=%ld, arg_count=%d, args=%p)",
		 sel_cc, NTHREAD_GET_ID(nthread), arg_count, args);
#endif /* ifdef LOG_LEVEL_3 */

	int8_t reg_arg_count = 0;

	int8_t i;
	for (i = 0; i < 8; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
		if (reg_index != 0)
			reg_arg_count++;
	}

	if (reg_arg_count > arg_count)
		reg_arg_count = arg_count;

	ntu_get_reg_args_ex(reg_arg_count, args, sel_cc);

	uint8_t push_arg_count = arg_count - reg_arg_count;
	if (push_arg_count > 0) {
		void *rsp = NTHREAD_GET_OREG(nthread, NTHREAD_RSP);
		void *wpos =
			(void *)((int8_t *)rsp + NTUCC_GET_STACK_ADD(sel_cc));

		size_t push_args_size = sizeof(void *) * push_arg_count;
		void **push_args = args + reg_arg_count;

		if (HAS_ERR(ntu_read_memory(wpos, (void *)push_args,
					    push_args_size)))
			return GET_ERR(NTUTILS_READ_MEMORY_ERROR);

		if ((sel_cc & NTUCC_REVERSE_OP) != 0) {
			void **push_args_copy = (void **)ntutils->stack_helper;
			memcpy(push_args_copy, push_args, push_args_size);

			uint8_t i;
			uint8_t helper = push_arg_count - 1;
			for (i = 0; i < push_arg_count; i++) {
				push_args[i] = push_args_copy[helper - i];
			}
		}
	}

	return N_OK;
}

NTHREAD_API nerror_t ntu_call_v(void *func_addr, uint8_t arg_count,
				va_list args)
{
	ntutils_t *ntutils = ntu_get();

	RET_ERR(ntu_set_args_v(arg_count, args));
	return nthread_call(&ntutils->nthread, func_addr, &ntutils->ret_value);
}

NTHREAD_API nerror_t ntu_call(void *func_addr, int arg_count, ...)
{
	va_list args;
	va_start(args, arg_count);

	nerror_t ret = ntu_call_v(func_addr, arg_count, args);

	va_end(args);
	return ret;
}

NTHREAD_API void *ntu_ucall_v(void *func_addr, int arg_count, va_list args)
{
	ntutils_t *ntutils = ntu_get();
	if (HAS_ERR(ntu_call_v(func_addr, arg_count, args)))
		return NULL;

	return ntutils->ret_value;
}

NTHREAD_API void *_ntu_ucall(void *func_addr, int arg_count, ...)
{
	va_list args;
	va_start(args, arg_count);

	nerror_t *ret = ntu_ucall_v(func_addr, arg_count, args);

	va_end(args);
	return ret;
}

NTHREAD_API void *ntu_memset(void *dest, int fill, size_t length)
{
	ntu_set_default_cc();
	return ntu_ucall(ntu_funcs.memset, dest, fill, length);
}

NTHREAD_API void *ntu_malloc(size_t size)
{
	ntu_set_default_cc();
	return ntu_ucall(ntu_funcs.malloc, size);
}

NTHREAD_API void ntu_free(void *address)
{
	ntu_set_default_cc();
	ntu_ucall(ntu_funcs.free, address);
}

NTHREAD_API FILE *ntu_fopen(const nfile_path_t filename,
			    const nfile_path_t mode)
{
	ntu_set_default_cc();
	return (FILE *)ntu_ucall(ntu_funcs.fopen, filename, mode);
}

NTHREAD_API size_t ntu_fread(void *buffer, size_t size, size_t count,
			     FILE *fstream)
{
	ntu_set_default_cc();
	return (size_t)ntu_ucall(ntu_funcs.fread, buffer, size, count, fstream);
}

NTHREAD_API size_t ntu_fwrite(const void *buffer, size_t size, size_t count,
			      FILE *fstream)
{
	ntu_set_default_cc();
	return (size_t)ntu_ucall(ntu_funcs.fwrite, buffer, size, count,
				 fstream);
}

NTHREAD_API int ntu_fflush(FILE *fstream)
{
	ntutils_t *ntutils = ntu_o(NTU_DEFAULT_CC);
	if (HAS_ERR(ntu_call(ntu_funcs.fflush, 1, fstream)))
		return -1;

	return (int)(int64_t)ntutils->ret_value;
}

NTHREAD_API int ntu_fclose(FILE *fstream)
{
	ntutils_t *ntutils = ntu_o(NTU_DEFAULT_CC);
	if (HAS_ERR(ntu_call(ntu_funcs.fclose, 1, fstream)))
		return -1;

	return (int)(int64_t)ntutils->ret_value;
}

NTHREAD_API void *ntu_alloc_str(const char *str)
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

NTHREAD_API nttunnel_t *ntu_nttunnel()
{
	ntutils_t *ntutils = ntu_get();
	return NTU_NTTUNNEL_EX(ntutils);
}

NTHREAD_API bool ntu_tunnel_can_read()
{
	nttunnel_t *nttunnel = ntu_nttunnel();
	return ntt_can_read(nttunnel);
}

NTHREAD_API bool ntu_tunnel_can_write()
{
	nttunnel_t *nttunnel = ntu_nttunnel();
	return ntt_can_write(nttunnel);
}

NTHREAD_API nerror_t ntu_tunnel_read(const void *dest, void *source,
				     size_t length)
{
	nttunnel_t *tunnel = ntu_nttunnel();
	return ntt_read(tunnel, dest, source, length);
}

NTHREAD_API nerror_t ntu_tunnel_write(void *dest, const void *source,
				      size_t length)
{
	nttunnel_t *tunnel = ntu_nttunnel();
	return ntt_write(tunnel, dest, source, length);
}
