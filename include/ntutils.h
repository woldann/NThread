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

#define NTUTILS_GET_LIBC_BASE_ERROR 0x7341
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

#if !defined(NTUTILS_DISABLE_GLOBAL_CC) || NTUTILS_DISABLE_GLOBAL_CC != 1

#ifdef __WIN32
#define NTU_GLOBAL_CC NTU_DEFAULT_CC
#endif // __WIN32

#endif // !defined(NTUTILS_DISABLE_GLOBAL_CC) || NTUTILS_DISABLE_GLOBAL_CC != 1

struct ntutils {
	void *ret_value;
	ntucc_t sel_cc;

	nttunnel_t nttunnel;

#ifdef __WIN32

	DWORD temp_path_len;
	void *temp_path_addr;

#endif /* ifdef __WIN32 */

	nthread_t nthread;
};

typedef struct ntutils ntutils_t;

ntutils_t *_ntu_get(void);

nerror_t ntu_set(ntutils_t *ntutils);

ntutils_t *ntu_resize(size_t new_size);

#define ntu_get() _ntu_get()

#define ntu_set_cc_ex(ntutils, cc) (ntutils->sel_cc = cc)

#ifndef NTU_GLOBAL_CC

void _ntu_set_cc(ntucc_t cc);

#define ntu_set_cc(cc) _ntu_set_cc(cc)

ntutils_t *_ntu_o(ntucc_t cc);

#define ntu_o(cc) _ntu_o(cc)

#else // NTU_GLOBAL_CC

#define ntu_set_cc(cc) \
	do {           \
	} while (0)
#define ntu_o(cc) ntu_get()

#endif // NTU_GLOBAL_CC

void *ntu_get_libc_base();

/**
 * @brief Initialize global state for ntutils subsystem.
 * 
 * @return Error code.
 */
nerror_t ntu_global_init(void);

/**
 * @brief Clean up global ntutils resources.
 */
void ntu_global_destroy(void);

/**
 * @brief Initialize an ntutils instance for a target thread with required context.
 * 
 * @param thread_id ID of the target thread.
 * @param push_reg_offset Register offset to be used for pushing data to the stack.
 *        Determines which register will hold the `push_addr` value.
 * @param push_addr Address used during argument pushing for calls.
 * @param sleep_addr Address used to pause/wait inside hijacked thread.
 * @return Error code.
 */
nerror_t ntu_init_ex(ntid_t thread_id, nthread_reg_offset_t push_reg_offset,
		     void *push_addr, void *sleep_addr);

/**
 * @brief Simplified version of ntu_init_ex using the best available register for argument pushing.
 * 
 * Internally calls `ntu_init_ex` with `NTHREAD_BEST_PUSH_REG` as the push register offset.
 *
 * @param thread_id ID of the target thread.
 * @param push_addr Address used during argument pushing for calls.
 * @param sleep_addr Address used to pause/wait inside hijacked thread.
 * @return Error code.
 */
nerror_t ntu_init(ntid_t thread_id, void *push_addr, void *sleep_addr);

/**
 * @brief Destroy the current ntutils instance and release resources.
 */
void ntu_destroy();

/**
 * @brief Call a function inside the target thread with variable arguments (va_list).
 * 
 * @param ntutils Pointer to the ntutils instance.
 * @param func_addr Address of the target function to call.
 * @param arg_count Number of arguments to pass.
 * @param args Variable argument list.
 * @return Error code.
 */
nerror_t ntu_call_v(ntutils_t *ntutils, void *func_addr, uint8_t arg_count,
		    va_list args);

/**
 * @brief Call a function inside the target thread with variadic arguments.
 * 
 * @param ntutils Pointer to the ntutils instance.
 * @param function_address Address of the function to call.
 * @param arg_count Number of arguments to pass.
 * @param ... Arguments to be passed to the function.
 * @return Error code.
 */
nerror_t ntu_call(ntutils_t *ntutils, void *function_address, uint8_t arg_count,
		  ...);

/**
 * @brief Call a function with variable arguments and retrieve a return value.
 * 
 * @param func_addr Address of the function to call.
 * @param arg_count Number of arguments to pass.
 * @param args Variable argument list.
 * @return Pointer returned by the called function
 */
void *ntu_ucall_v(void *func_addr, uint8_t arg_count, va_list args);

/**
 * @brief Call a function with variadic arguments and retrieve a return value.
 * 
 * @param func_addr Address of the function to call.
 * @param arg_count Number of arguments to pass.
 * @param ... Arguments to be passed.
 * @return Pointer returned by the called function
 */
void *ntu_ucall(void *func_addr, uint8_t arg_count, ...);

/**
 * @brief Fill a block of memory in the target process with a specified value.
 * 
 * @param dest Destination address.
 * @param fill Value to fill with.
 * @param length Number of bytes to fill.
 * @return Pointer to the destination.
 */
void *ntu_memset(void *dest, int fill, size_t length);

/**
 * @brief Allocate memory inside the target process.
 * 
 * @param size Number of bytes to allocate.
 * @return Pointer to allocated memory.
 */
void *ntu_malloc(size_t size);

/**
 * @brief Free previously allocated memory inside the target process.
 * 
 * @param address Pointer to memory to free.
 */
void ntu_free(void *address);

/**
 * @brief Open a file stream inside the target process.
 * 
 * @param filename File path in the target process's memory.
 * @param mode Mode string in the target process's memory.
 * @return FILE pointer representing the opened file stream.
 *
 * @note Strings must exist in the target process memory prior to calling this function.
 */
FILE *ntu_fopen(const nfile_path_t filename, const nfile_path_t mode);

/**
 * @brief Read from a file stream into a buffer.
 * 
 * @param buffer Destination buffer.
 * @param size Size of each element.
 * @param count Number of elements to read.
 * @param fstream FILE pointer of the opened file stream.
 * @return Number of elements successfully read.
 */
size_t ntu_fread(void *buffer, size_t size, size_t count, FILE *fstream);

/**
 * @brief Write data from a buffer into a file stream.
 * 
 * @param buffer Source buffer.
 * @param size Size of each element.
 * @param count Number of elements to write.
 * @param fstream FILE pointer of the opened file stream.
 * @return Number of elements successfully written.
 */
size_t ntu_fwrite(const void *buffer, size_t size, size_t count, FILE *fstream);

/**
 * @brief Flush the file stream buffers.
 * 
 * @param fstream FILE pointer of the opened file stream.
 * @return 0 on success.
 */
int ntu_fflush(FILE *fstream);

/**
 * @brief Close the opened file stream.
 * 
 * @param fstream FILE pointer to close.
 * @return 0 on success.
 */
int ntu_fclose(FILE *fstream);

/**
 * @brief Allocate and copy a string into the target process memory.
 * 
 * @param str Source null-terminated string.
 * @return Pointer to the allocated string in target memory.
 */
void *ntu_alloc_str(const char *str);

/**
 * @brief Write data to target memory and clear any remaining bytes with memset.
 * 
 * @param dest Destination memory address.
 * @param source Source data buffer.
 * @param length Number of bytes to write.
 * @param last_dest Pointer to the last written destination byte (optional).
 * @return Error code.
 */
nerror_t ntu_write_with_memset_ex(void *dest, const void *source, size_t length,
				  const void *last_dest);

/**
 * @brief Write data to remote memory using memset-based operations.
 *
 * @param dest Destination address in remote memory.
 * @param source Source buffer to write from.
 * @param length Number of bytes to write.
 * @return Error code indicating success or failure.
 */
nerror_t ntu_write_with_memset(void *dest, const void *source, size_t length);

nerror_t ntu_write_with_memset(void *dest, const void *source, size_t length);

#define NTU_NTTUNNEL_EX(ntutils) (&ntutils->nttunnel)
#define NTU_NTTUNNEL() (ntu_nttunnel())

nttunnel_t *ntu_nttunnel();

bool ntu_tunnel_can_read();

bool ntu_tunnel_can_write();

nerror_t ntu_tunnel_read(const void *dest, void *source, size_t length);

nerror_t ntu_tunnel_write(void *dest, const void *source, size_t length);

#define ntu_read(...) ntu_tunnel_read(__VA_ARGS__)
#define ntu_write(...) ntu_tunnel_write(__VA_ARGS__)

#define ntu_read_memory(...) ntu_tunnel_read(__VA_ARGS__)
#define ntu_write_memory(...) ntu_tunnel_write(__VA_ARGS__)

#endif // !__NTUTILS_H__
