/*
 * Copyright (C) 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#ifndef __NTMEM_H__
#define __NTMEM_H__

#define NTMEM_DEFAULT_LENGTH 1024

#include "neptune.h"

#define NTMEM_SAFE_WRITE 0x01

typedef int8_t nmem_flags_t; 

typedef struct nttunnel nttunnel_t;

struct ntmem {
  nmem_flags_t flags;

  size_t length;
  void *remote_mem;
};

#define NTM_LENGTH(ntmem) (ntmem->length)
#define NTM_SET_LENGTH(ntmem, set_length) (ntmem->length = (set_length))

#define NTM_CALC_LOCAL_SIZE(length) (length * 2 * sizeof(int8_t))
#define NTM_LOCAL_SIZE(ntmem) (NTM_CALC_LOCAL_SIZE(ntmem->length))
#define NTM_CALC_STRUCT_SIZE(length) (sizeof(ntmem_t) + NTM_CALC_LOCAL_SIZE(length))
#define NTM_STRUCT_SIZE(ntmem) (NTM_CALC_STRUCT_SIZE(ntmem->length))

#define NTM_SET_REMOTE(ntmem, set_remote_mem) (ntmem->remote_mem = (set_remote_mem))
#define NTM_REMOTE(ntmem) (ntmem->remote_mem)
#define NTM_LOCAL(ntmem) ((void*) (ntmem + 1))
#define NTM_LOCAL_CPY(ntmem) (NTM_LOCAL(ntmem) + NTM_LENGTH(ntmem))

typedef struct ntmem ntmem_t;

#define NTMEM_ERROR 0x9200
#define NTMEM_ALLOC_ERROR 0x9201
#define NTMEM_NTU_MALLOC_ERROR 0x9202
#define NTMEM_NTU_MEMSET_ERROR 0x9203
#define NTMEM_PUSH_WITH_TUNNEL_ERROR 0x9204
#define NTMEM_PUSH_WITH_MEMSET_ERROR 0x9205

#include "ntutils.h"

void ntm_enable_safe_write(ntmem_t *ntmem);

void ntm_disable_safe_write(ntmem_t *ntmem);

bool ntm_is_safe_write(ntmem_t *ntmem);

nerror_t ntm_init(ntmem_t *ntmem);

void ntm_destroy(ntmem_t *ntmem);

ntmem_t *ntm_create_ex(size_t length);

ntmem_t *ntm_create();

void ntm_delete(ntmem_t *ntmem);

void *ntm_delete_s(ntmem_t *ntmem);


void *ntm_pull_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel);

void *ntm_push_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel);

void *ntm_push_with_memset(ntmem_t *ntmem);

void *ntm_push(ntmem_t *ntmem, nttunnel_t *nttunnel);

#endif // !__NTUTILS_BUFFER_H__

