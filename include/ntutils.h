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

/**
 * @file ntutils.h
 * @brief Extended nthread utilities for advanced function calls and memory manipulation.
 *
 * Provides enhanced capabilities for invoking functions inside target threads/processes,
 * along with safe memory operations such as cross-process memory write, allocation,
 * and buffered file I/O emulation. Built on top of NThread's core thread manipulation,
 * ntutils adds flexible argument passing, memory memset-based writing, and file stream
 * operations tailored for remote contexts.
 */

#ifndef __NTUTILS_H__
#define __NTUTILS_H__

#include "nerror.h"
#include "nthread.h"
#include "ntucc.h"

#define NTU_DEFAULT_CC NTUCC_DEFAULT

#ifdef _WIN32
#define NTU_DEFAULT_PFA_CC NTUCC_WINDOWS_X64_PASS_RCX
#define NTU_DEFAULT_CC_FA NTHREAD_RCX
#else // !_WIN32
#define NTU_DEFAULT_PFA_CC NTUCC_CDECL_PASS_
#define NTU_DEFAULT_CC_FA NTHREAD_RCX
#endif // !_WIN32

#define NTUTILS_ERROR 0x7340

#define NTUTILS_GET_LIBC_BASE_ERROR 0x7341
#define NTUTILS_UNKNOWN_CC_ERROR 0x7342
#define NTUTILS_ALLOC_ERROR 0x7343
#define NTUTILS_TLS_SET_VALUE_ERROR 0x7344
#define NTUTILS_TLS_ALLOC_ERROR 0x7345
#define NTUTILS_NTU_MEMSET_ERROR 0x7346
#define NTUTILS_NTU_WRITE_WITH_MEMSET_ERROR 0x7347
#define NTUTILS_NTU_WRITE_WITH_MEMSET_DEST_ERROR 0x7348
#define NTUTILS_NTM_CREATE_EX_ERROR 0x7349
#define NTUTILS_NTM_RESET_REMOTE_EX_ERROR 0x734A
#define NTUTILS_NTM_PUSH_ERROR 0x734B
#define NTUTILS_NTHREAD_ERROR 0x734C
#define NTUTILS_NTU_RESIZE_ERROR 0x734D
#define NTUTILS_NTHREAD_INIT_ERROR 0x734E
#define NTUTILS_NTT_INIT_ERROR 0x734F
#define NTUTILS_READ_MEMORY_ERROR 0x7350
#define NTUTILS_WRITE_MEMORY_ERROR 0x7351
#define NTUTILS_NTU_GET_ERROR 0x7352

#define NTUTILS_FUNC_INIT_ERROR 0x7360
#define NTUTILS_FUNC_INIT_ERROR_E (NTUTILS_FUNC_INIT_ERROR + 7)

#define NTUTILS_ERROR_E NTUTILS_FUNC_INIT_ERROR_E

#include "nttunnel.h"

#if !defined(NTUTILS_DISABLE_GLOBAL_CC) || NTUTILS_DISABLE_GLOBAL_CC != 1

#ifdef _WIN32
#define NTU_GLOBAL_CC NTU_DEFAULT_CC
#endif // _WIN32

#endif // !defined(NTUTILS_DISABLE_GLOBAL_CC) || NTUTILS_DISABLE_GLOBAL_CC != 1

struct ntutils {
	void *ret_value;
	ntucc_t sel_cc;

	nttunnel_t nttunnel;
	int8_t stack_helper[255 * sizeof(void *)];

	nthread_t nthread;
};

typedef struct ntutils ntutils_t;

NTHREAD_API ntutils_t *_ntu_get(void);

NTHREAD_API nerror_t ntu_set(ntutils_t *ntutils);

NTHREAD_API nerror_t ntu_resize(size_t new_size);

#define ntu_get() _ntu_get()

#define ntu_set_cc_ex(ntutils, cc) (ntutils->sel_cc = cc)

#ifndef NTU_GLOBAL_CC

NTHREAD_API void _ntu_set_cc(ntucc_t cc);

#define ntu_set_cc(cc) _ntu_set_cc(cc)

NTHREAD_API void _ntu_set_default_cc();

#define ntu_set_default_cc() _ntu_set_default_cc()

NTHREAD_API ntutils_t *_ntu_o(ntucc_t cc);

#define ntu_o(cc) _ntu_o(cc)

#else // NTU_GLOBAL_CC

#define ntu_set_cc(cc) \
	do {           \
	} while (0)

#define ntu_set_default_cc() \
	do {                 \
	} while (0)

#define ntu_o(cc) ntu_get()

#endif // NTU_GLOBAL_CC

NTHREAD_API void *ntu_get_libc_base();

/**
 * @brief Initialize global state for ntutils subsystem.
 * 
 * @return Error code.
 */
NTHREAD_API nerror_t ntu_global_init(void);

/**
 * @brief Clean up global ntutils resources.
 */
NTHREAD_API void ntu_global_destroy(void);

NTHREAD_API nerror_t ntu_upgrade(nthread_t *nthread);

NTHREAD_API nerror_t ntu_attach_ex(ntid_t thread_id,
				   nthread_reg_offset_t push_reg_offset,
				   void *push_addr, void *sleep_addr);

NTHREAD_API nerror_t ntu_attach(ntid_t thread_id, void *push_addr,
				void *sleep_addr);

/**
 * @brief Destroy the current ntutils instance and release resources.
 */
NTHREAD_API void ntu_destroy();

NTHREAD_API void ntu_set_reg_args_ex(uint8_t arg_count, void **args,
				     ntucc_t sel_cc);

/**
 * @brief Set register arguments directly using an array of values
 * 
 * @param arg_count Number of arguments to set
 * @param args Array of argument values to put in registers
 */
NTHREAD_API void ntu_set_reg_args(uint8_t arg_count, void **args);

/**
 * @brief Set arguments using a va_list
 * 
 * @param arg_count Number of arguments in the va_list
 * @param args Variable argument list containing the arguments
 * @return nerror_t error code
 */
NTHREAD_API nerror_t ntu_set_args_v(uint8_t arg_count, va_list args);

/**
 * @brief Set arguments using variadic parameters
 * 
 * @param arg_count Number of arguments to set
 * @param ... Variable arguments to set
 * @return nerror_t error code
 */
NTHREAD_API nerror_t ntu_set_args(int arg_count, ...);

NTHREAD_API void ntu_get_reg_args_ex(uint8_t arg_count, void **args,
				     ntucc_t sel_cc);

/**
 * @brief Get current register argument values
 * 
 * @param arg_count Number of arguments to retrieve
 * @param args Array to store retrieved argument values
 */
NTHREAD_API void ntu_get_reg_args(uint8_t arg_count, void **args);

/**
 * @brief Get current argument values
 * 
 * @param arg_count Number of arguments to retrieve
 * @param args Array to store retrieved argument values
 * @return nerror_t error code
 */
NTHREAD_API nerror_t ntu_get_args(uint8_t arg_count, void **args);

/**
 * @brief Call a function inside the target thread with variable arguments (va_list).
 * 
 * @param func_addr Address of the target function to call.
 * @param arg_count Number of arguments to pass.
 * @param args Variable argument list.
 * @return Error code.
 */
NTHREAD_API nerror_t ntu_call_v(void *func_addr, uint8_t arg_count,
				va_list args);

/**
 * @brief Call a function inside the target thread with variadic arguments.
 * 
 * @param ntutils Pointer to the ntutils instance.
 * @param func_addr Address of the function to call.
 * @param arg_count Number of arguments to pass.
 * @param ... Arguments to be passed to the function.
 * @return Error code.
 */
NTHREAD_API nerror_t ntu_call(void *func_addr, int arg_count, ...);

/**
 * @brief Call a function with variable arguments and retrieve a return value.
 * 
 * @param func_addr Address of the function to call.
 * @param arg_count Number of arguments to pass.
 * @param args Variable argument list.
 * @return Pointer returned by the called function
 */
NTHREAD_API void *ntu_ucall_v(void *func_addr, int arg_count, va_list args);

/**
 * @brief Call a function with variadic arguments and retrieve a return value.
 * 
 * @param func_addr Address of the function to call.
 * @param arg_count Number of arguments to pass.
 * @param ... Arguments to be passed.
 * @return Pointer returned by the called function
 */
NTHREAD_API void *_ntu_ucall(void *func_addr, int arg_count, ...);

#define ntu_ucall(func_addr, ...) \
	_ntu_ucall(func_addr, NEPTUNE_GET_ARG_COUNT(__VA_ARGS__), __VA_ARGS__)

/**
 * @brief Fill a block of memory in the target process with a specified value.
 * 
 * @param dest Destination address.
 * @param fill Value to fill with.
 * @param length Number of bytes to fill.
 * @return Pointer to the destination.
 */
NTHREAD_API void *ntu_memset(void *dest, int fill, size_t length);

/**
 * @brief Allocate memory inside the target process.
 * 
 * @param size Number of bytes to allocate.
 * @return Pointer to allocated memory.
 */
NTHREAD_API void *ntu_malloc(size_t size);

/**
 * @brief Free previously allocated memory inside the target process.
 * 
 * @param address Pointer to memory to free.
 */
NTHREAD_API void ntu_free(void *address);

/**
 * @brief Open a file stream inside the target process.
 * 
 * @param filename File path in the target process's memory.
 * @param mode Mode string in the target process's memory.
 * @return FILE pointer representing the opened file stream.
 *
 * @note Strings must exist in the target process memory prior to calling this function.
 */
NTHREAD_API FILE *ntu_fopen(const nfile_path_t filename,
			    const nfile_path_t mode);

/**
 * @brief Read from a file stream into a buffer.
 * 
 * @param buffer Destination buffer.
 * @param size Size of each element.
 * @param count Number of elements to read.
 * @param fstream FILE pointer of the opened file stream.
 * @return Number of elements successfully read.
 */
NTHREAD_API size_t ntu_fread(void *buffer, size_t size, size_t count,
			     FILE *fstream);

/**
 * @brief Write data from a buffer into a file stream.
 * 
 * @param buffer Source buffer.
 * @param size Size of each element.
 * @param count Number of elements to write.
 * @param fstream FILE pointer of the opened file stream.
 * @return Number of elements successfully written.
 */
NTHREAD_API size_t ntu_fwrite(const void *buffer, size_t size, size_t count,
			      FILE *fstream);

/**
 * @brief Flush the file stream buffers.
 * 
 * @param fstream FILE pointer of the opened file stream.
 * @return 0 on success.
 */
NTHREAD_API int ntu_fflush(FILE *fstream);

/**
 * @brief Close the opened file stream.
 * 
 * @param fstream FILE pointer to close.
 * @return 0 on success.
 */
NTHREAD_API int ntu_fclose(FILE *fstream);

/**
 * @brief Allocate and copy a string into the target process memory.
 * 
 * @param str Source null-terminated string.
 * @return Pointer to the allocated string in target memory.
 */
NTHREAD_API void *ntu_alloc_str(const char *str);

/**
 * @brief Write data to remote memory, skipping bytes equal to the given value.
 *
 * This function writes only the bytes from `source` that are not equal to `last_value`.
 * It avoids writing bytes with the same value to reduce memory operations.
 *
 * @param dest Destination address in remote memory.
 * @param source Source buffer to write from.
 * @param length Number of bytes to write.
 * @param last_value Value to skip while writing (e.g., 0x00 or 0xFF).
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t ntu_write_with_memset_value(void *dest, const void *source,
						 size_t length,
						 int8_t last_value);

/**
 * @brief Write data to remote memory, skipping identical bytes by comparing with last written destination.
 *
 * This function compares the `source` buffer with the memory at `last_dest` and only writes bytes that differ.
 * Both `source` and `last_dest` are expected to be in local (current process) memory.
 *
 * @param dest Destination address in remote memory.
 * @param source Source buffer to write from (local memory).
 * @param length Number of bytes to write.
 * @param last_dest Last written destination buffer for comparison (local memory, required).
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t ntu_write_with_memset_dest(void *dest, const void *source,
						size_t length,
						const void *last_dest);

/**
 * @brief Write data to remote memory using memset-based operations.
 *
 * This function writes the entire source buffer to the destination address
 * using memory write techniques based on memset.
 *
 * @param dest Destination address in remote memory.
 * @param source Source buffer to write from.
 * @param length Number of bytes to write.
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t ntu_write_with_memset(void *dest, const void *source,
					   size_t length);

#define NTU_NTTUNNEL_EX(ntutils) (&ntutils->nttunnel)
#define NTU_NTTUNNEL() (ntu_nttunnel())

NTHREAD_API nttunnel_t *ntu_nttunnel();

NTHREAD_API bool ntu_tunnel_can_read();

NTHREAD_API bool ntu_tunnel_can_write();

NTHREAD_API nerror_t ntu_tunnel_read(const void *dest, void *source,
				     size_t length);

NTHREAD_API nerror_t ntu_tunnel_write(void *dest, const void *source,
				      size_t length);

#define ntu_read(...) ntu_tunnel_read(__VA_ARGS__)
#define ntu_write(...) ntu_tunnel_write(__VA_ARGS__)

#define ntu_read_memory(...) ntu_tunnel_read(__VA_ARGS__)
#define ntu_write_memory(...) ntu_tunnel_write(__VA_ARGS__)

#endif // !__NTUTILS_H__
