/*
 * Copyright (C) 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#ifndef __NTTUNNEL_H__
#define __NTTUNNEL_H__

#include "neptune.h"

#ifdef __WIN32
#define NTUTILS_SFILE_MAX_PATH_LENGTH MAX_PATH
#endif // __WIN32

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

#define NTTUNNEL_FSCHAN_DEFAULT_FLAGS NTTUNNEL_FSCHAN_MAX_TRANSFER_262144 | NTTUNNEL_FSCHAN_CREATE_TEMP_PATH

#define NTTUNNEL_FSCHAN_MAX_MODE_SIZE 6

#define NTTUNNEL_FSCHAN_CALC_MAX_TRANSFER(flags) (((size_t) 4) << (6 + (flags & 0x07) * 2))

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
#define NTTUNNEL_NTM_PUSH_MEMSET_ERROR 0x7605
#define NTTUNNEL_NTU_FOPEN_ERROR 0x7606
#define NTTUNNEL_NFILE_WRITE_ERROR 0x7607
#define NTTUNNEL_NFILE_READ_ERROR 0x7608
#define NTTUNNEL_NTU_FREAD_ERROR 0x7609
#define NTTUNNEL_NTU_FWRITE_ERROR 0x760a
#define NTTUNNEL_NTU_FFLUSH_ERROR 0x760b
#define NTTUNNEL_INIT_FSCHAN_ERROR 0x760c
#define NTTUNNEL_CREATE_TEMP_PATH_ERROR 0x760d
#define NTTUNNEL_NTM_CREATE_ERROR 0x760f

#include "ntutils.h"

bool ntt_can_read(nttunnel_t *nttunnel);

bool ntt_can_write(nttunnel_t *nttunnel);

nerror_t ntt_init_ex(nttunnel_t *nttunnel, nttunnel_fschan_flags_t flags);

nerror_t ntt_init(nttunnel_t *nttunnel);

void ntt_destroy(nttunnel_t *nttunnel);


nerror_t ntt_read(nttunnel_t *nttunnel, const void *dest, void *source, size_t length);

nerror_t ntt_write(nttunnel_t *nttunnel, void *dest, const void *source, size_t length);

#endif // !__NTTUNNEL_H__
