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
 * @file ntmem.h
 * @brief Provides a memory synchronization mechanism between processes.
 *
 * This module facilitates shared memory management for inter-process communication,
 * supporting both safe and unsafe write modes. When safe write is disabled, memory
 * synchronization is performed using more minimal data transfers.
 *
 * Writing operations are performed using `nttunnel` or `ntu_write_with_memset`.
 */

#ifndef __NTMEM_H__
#define __NTMEM_H__

#define NTMEM_DEFAULT_LENGTH 1024

#include "neptune.h"

#define NTMEM_SAFE_WRITE 0x10

typedef int8_t ntmem_flags_t;

typedef struct nttunnel nttunnel_t;

struct ntmem {
	ntmem_flags_t flags;

	size_t length;
	void *remote_mem;
};

#define NTM_LENGTH(ntmem) (ntmem->length)
#define NTM_SET_LENGTH(ntmem, set_length) (ntmem->length = (set_length))

#define NTM_CALC_LOCALS_SIZE(length) (length * 2 * sizeof(int8_t))
#define NTM_CALC_STRUCT_SIZE(length) \
	(sizeof(ntmem_t) + NTM_CALC_LOCALS_SIZE(length))
#define NTM_STRUCT_SIZE(ntmem) (NTM_CALC_STRUCT_SIZE(ntmem->length))

#define NTM_SET_REMOTE(ntmem, set_remote_mem) \
	(ntmem->remote_mem = (set_remote_mem))
#define NTM_REMOTE(ntmem) (ntmem->remote_mem)
#define NTM_LOCAL(ntmem) ((void *)(ntmem + 1))
#define NTM_LOCAL_CPY(ntmem) \
	((void *)(((int8_t *)NTM_LOCAL(ntmem)) + NTM_LENGTH(ntmem)))

typedef struct ntmem ntmem_t;

#define NTMEM_ERROR 0x9200

#define NTMEM_ALLOC_ERROR 0x9201
#define NTMEM_NTU_MALLOC_ERROR 0x9202
#define NTMEM_NTM_RESET_REMOTE_ERROR 0x9203
#define NTM_ALLOC_REMOTE_ERROR 0x9204

#define NTMEM_ERROR_E NTMEM_PUSH_WITH_MEMSET_ERROR

#include "ntutils.h"

/**
 * @brief Enable safe write mode for memory synchronization.
 *
 * @param ntmem Pointer to memory structure.
 */
NTHREAD_API void ntm_enable_safe_write(ntmem_t *ntmem);

/**
 * @brief Disable safe write mode for memory synchronization.
 *
 * @param ntmem Pointer to memory structure.
 */
NTHREAD_API void ntm_disable_safe_write(ntmem_t *ntmem);

/**
 * @brief Check if safe write mode is enabled.
 *
 * @param ntmem Pointer to memory structure.
 * @return true if safe write mode is enabled, false otherwise.
 */
NTHREAD_API bool ntm_is_safe_write(ntmem_t *ntmem);

NTHREAD_API void *ntm_reset_locals(ntmem_t *ntmem);

NTHREAD_API void *ntm_reset_remote_ex(ntmem_t *ntmem, size_t length);

NTHREAD_API void *ntm_reset_remote(ntmem_t *ntmem);

NTHREAD_API nerror_t ntm_reset(ntmem_t *ntmem);

NTHREAD_API void *ntm_alloc_remote(ntmem_t *ntmem);

NTHREAD_API void ntm_free_remote(ntmem_t *ntmem);

NTHREAD_API void *ntm_alloc_remote_and_reset(ntmem_t *ntmem);

/**
 * @brief Create and initialize a new memory structure with specific length.
 *
 * @param length Memory size in bytes.
 * @return Pointer to newly created memory structure.
 */
NTHREAD_API ntmem_t *ntm_create_ex(size_t length);

/**
 * @brief Create and initialize a memory structure with default size.
 *
 * @return Pointer to newly created memory structure.
 */
NTHREAD_API ntmem_t *ntm_create();

NTHREAD_API ntmem_t *ntm_create_with_alloc_ex(size_t length);

NTHREAD_API ntmem_t *ntm_create_with_alloc();

NTHREAD_API ntmem_t *ntm_create_from_remote(void *remote, size_t length);

/**
 * @brief Delete memory structure.
 *
 * @param ntmem Pointer to memory structure.
 */
NTHREAD_API void ntm_delete(ntmem_t *ntmem);

NTHREAD_API void ntm_delete_and_free(ntmem_t *ntmem);

/**
 * @brief Delete the ntmem structure and detach remote memory pointer.
 *
 * Frees the local `ntmem_t` structure and its local memory buffer,
 * but returns the remote memory address (in target process) to the caller.
 *
 * This allows the caller to continue interacting with the remote memory
 * even after the local structure is destroyed.
 *
 * @param ntmem Pointer to memory structure.
 * @return Pointer to remote memory address in target process.
 */
NTHREAD_API void *ntm_delete_and_detach(ntmem_t *ntmem);

NTHREAD_API void *ntm_pull_with_tunnel_ex(ntmem_t *ntmem, nttunnel_t *nttunnel,
					  size_t len);

/**
 * @brief Pull data from tunnel into the memory buffer.
 *
 * @param ntmem Pointer to memory structure.
 * @param nttunnel Associated tunnel structure.
 * @return Pointer to updated buffer.
 */
NTHREAD_API void *ntm_pull_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel);

/**
 * @brief Push memory buffer into target process using tunnel.
 *
 * @param ntmem Pointer to memory structure.
 * @param nttunnel Associated tunnel structure.
 * @return Pointer to pushed data location.
 */
NTHREAD_API void *ntm_push_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel);

/**
 * @brief Push memory buffer using memset as a writing method.
 *
 * @param ntmem Pointer to memory structure.
 * @return Pointer to pushed data location.
 */
NTHREAD_API void *ntm_push_with_memset(ntmem_t *ntmem);

/**
 * @brief Push memory buffer into target using default method (tunnel or memset).
 *
 * @param ntmem Pointer to memory structure.
 * @param nttunnel Associated tunnel structure.
 * @return Pointer to pushed data location.
 */
NTHREAD_API void *ntm_push_ex(ntmem_t *ntmem, nttunnel_t *nttunnel);

/**
 * @brief Push memory buffer into target using default method.
 *
 * Wrapper for `ntm_push_ex` that uses the default tunnel from `ntu_nttunnel`.
 *
 * @param ntmem Pointer to memory structure.
 * @return Pointer to pushed data location.
 */
NTHREAD_API void *ntm_push(ntmem_t *ntmem);

#endif // !__NTUTILS_BUFFER_H__
