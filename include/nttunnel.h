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
 * @file nttunnel.h
 * @brief High-level memory tunnel utilities using filesystem channel (FSCHAN).
 *
 * This module provides advanced memory read/write capabilities by building on top
 * of the basic `ntutils` operations. It introduces a read mechanism and improves
 * write operations via a virtual tunnel abstraction. 
 *
 * It uses `ntu_write_with_memset` internally for memory writes.
 * 
 * FSCHAN (File System Channel) refers to the logical memory communication channel
 * established between processes or within the same process context.
 */

#ifndef __NTTUNNEL_H__
#define __NTTUNNEL_H__

#include "nthread.h"
#include "nfile.h"

#define NTTUNNEL_FSCHAN_MAX_TRANSFER_256 0x00
#define NTTUNNEL_FSCHAN_MAX_TRANSFER_1024 0x01
#define NTTUNNEL_FSCHAN_MAX_TRANSFER_4096 0x02
#define NTTUNNEL_FSCHAN_MAX_TRANSFER_16384 0x03
#define NTTUNNEL_FSCHAN_MAX_TRANSFER_65536 0x04
#define NTTUNNEL_FSCHAN_MAX_TRANSFER_262144 0x05
#define NTTUNNEL_FSCHAN_MAX_TRANSFER_1048576 0x06
#define NTTUNNEL_FSCHAN_MAX_TRANSFER_4194304 0x07
#define NTTUNNEL_FSCHAN_DONT_SAVE_PATH 0x08
#define NTTUNNEL_FSCHAN_WRITE_MODE 0x10
#define NTTUNNEL_FSCHAN_CREATE_TEMP_PATH 0x20

#define NTTUNNEL_FSCHAN_DEFAULT_FLAGS \
	NTTUNNEL_FSCHAN_MAX_TRANSFER_262144 | NTTUNNEL_FSCHAN_CREATE_TEMP_PATH

#define NTTUNNEL_FSCHAN_MAX_MODE_SIZE 6

#define NTTUNNEL_FSCHAN_CALC_MAX_TRANSFER(flags) \
	(((size_t)4) << (6 + (flags & 0x07) * 2))

typedef int8_t nttunnel_fschan_flags_t;

struct nttunnel_fschan {
	void *remote_file;
	nfile_t local_file;

	nfile_path_t path;
};

typedef struct nttunnel_fschan nttunnel_fschan_t;

typedef struct ntmem ntmem_t;

struct nttunnel {
	ntmem_t *ntmem;

	nttunnel_fschan_t read;
	size_t read_transfer;

	nttunnel_fschan_t write;
	size_t write_transfer;

	size_t max_transfer;
};

typedef struct nttunnel nttunnel_t;

#define NTTUNNEL_ERROR 0x7600

#define NTTUNNEL_GET_TEMP_PATH_ERROR 0x7601
#define NTTUNNEL_GET_TEMP_FILE_ERROR 0x7602
#define NTTUNNEL_ALLOC_ERROR 0x7603
#define NTTUNNEL_NFILE_OPEN_ERROR 0x7604
#define NTTUNNEL_NTM_PUSH_ERROR 0x7605
#define NTTUNNEL_NTU_FOPEN_ERROR 0x7606
#define NTTUNNEL_NFILE_WRITE_ERROR 0x7607
#define NTTUNNEL_NFILE_READ_ERROR 0x7608
#define NTTUNNEL_NTU_FREAD_ERROR 0x7609
#define NTTUNNEL_NTU_FWRITE_ERROR 0x760A
#define NTTUNNEL_NTU_FFLUSH_ERROR 0x760B
#define NTTUNNEL_INIT_FSCHAN_ERROR 0x760C
#define NTTUNNEL_CREATE_TEMP_PATH_ERROR 0x760D
#define NTTUNNEL_NTM_CREATE_WITH_ALLOC_EX_ERROR 0x760E

#define NTTUNNEL_ERROR_E NTTUNNEL_NTM_CREATE_ERROR

/**
 * @brief Check if the tunnel is ready for reading.
 *
 * @param nttunnel Pointer to the tunnel structure.
 * @return true if reading is available; false otherwise.
 */
NTHREAD_API bool ntt_can_read(nttunnel_t *nttunnel);

/**
 * @brief Check if the tunnel is ready for writing.
 *
 * @param nttunnel Pointer to the tunnel structure.
 * @return true if writing is available; false otherwise.
 */
NTHREAD_API bool ntt_can_write(nttunnel_t *nttunnel);

/**
 * @brief Initialize the tunnel with specific FSCHAN flags.
 *
 * @param nttunnel Pointer to the tunnel structure.
 * @param flags Flags controlling tunnel behavior.
 * @return Error code.
 */
NTHREAD_API nerror_t ntt_init_ex(nttunnel_t *nttunnel,
				 nttunnel_fschan_flags_t flags);

/**
 * @brief Initialize the tunnel with default settings.
 *
 * @param nttunnel Pointer to the tunnel structure.
 * @return Error.
 */
NTHREAD_API nerror_t ntt_init(nttunnel_t *nttunnel);

/**
 * @brief Clean up and release resources associated with the tunnel.
 *
 * @param nttunnel Pointer to the tunnel structure.
 */
NTHREAD_API void ntt_destroy(nttunnel_t *nttunnel);

/**
 * @brief Read memory through the tunnel.
 *
 * @param nttunnel Pointer to the tunnel structure.
 * @param dest Address in local memory to copy data into.
 * @param source Source address in the remote or target memory.
 * @param length Number of bytes to read.
 * @return Error code.
 */
NTHREAD_API nerror_t ntt_read(nttunnel_t *nttunnel, const void *dest,
			      void *source, size_t length);

/**
 * @brief Write memory through the tunnel.
 *
 * This function uses `ntu_write_with_memset` internally to perform the memory write.
 *
 * @param nttunnel Pointer to the tunnel structure.
 * @param dest Destination address in the remote or target memory.
 * @param source Local buffer to write from.
 * @param length Number of bytes to write.
 * @return Error code.
 */
NTHREAD_API nerror_t ntt_write(nttunnel_t *nttunnel, void *dest,
			       const void *source, size_t length);

#endif // !__NTTUNNEL_H__
