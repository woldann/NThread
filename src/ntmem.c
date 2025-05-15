/*
 * Copyright (C) 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#include "ntmem.h"
#include "nttunnel.h"
#include "nmem.h"

void ntm_enable_safe_write(ntmem_t *ntmem)
{
  ntmem->flags |= NTMEM_SAFE_WRITE;
}

void ntm_disable_safe_write(ntmem_t *ntmem)
{
  ntmem->flags &=~(NTMEM_SAFE_WRITE);
}

bool ntm_is_safe_write(ntmem_t *ntmem)
{
  return (ntmem->flags & NTMEM_SAFE_WRITE) != 0;
}

nerror_t
ntm_init(ntmem_t *ntmem)
{
  void *mem = NTM_LOCAL(ntmem);
  size_t len = NTM_LENGTH(ntmem);

  memset(mem, 0, NTM_LOCAL_SIZE(ntmem));


  NTM_SET_REMOTE(ntmem, ntu_malloc(len));
  if (NTM_REMOTE(ntmem) == NULL)
    return GET_ERR(NTMEM_NTU_MALLOC_ERROR);

  if (ntu_memset(NTM_REMOTE(ntmem), 0, len) == NULL) {
    ntm_destroy(ntmem);
    return GET_ERR(NTMEM_NTU_MEMSET_ERROR);
  }

  return N_OK;
}

void
ntm_destroy(ntmem_t *ntmem)
{
  if (ntmem == NULL)
    return;

  if (NTM_REMOTE(ntmem) != NULL) {
    ntu_free(NTM_REMOTE(ntmem));
    NTM_SET_REMOTE(ntmem, NULL);
  }
}

ntmem_t *ntm_create_ex(size_t length)
{
  ntmem_t *ntmem = N_ALLOC(sizeof(ntmem_t) + (length * 2 * sizeof(int8_t)));
  if (ntmem == NULL)
    return NULL;

  NTM_SET_LENGTH(ntmem, length);
  if (HAS_ERR(ntm_init(ntmem))) {
    ntm_delete(ntmem);
    return NULL;
  }

  return ntmem;
}

ntmem_t *ntm_create()
{
  return ntm_create_ex(NTMEM_DEFAULT_LENGTH);
}

void ntm_delete(ntmem_t *ntmem)
{
  ntm_destroy(ntmem);
  N_FREE(ntmem);
}

void *ntm_delete_s(ntmem_t *ntmem)
{
  void *rmem = NTM_REMOTE(ntmem);
  N_FREE(ntmem);
  return rmem;
}

void *
ntm_pull_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel)
{

#ifdef LOG_LEVEL_3
  LOG_INFO("ntm_pull(ntmem=%p, nttunnel=%p)", ntmem, nttunnel);
#endif /* ifdef LOG_LEVEL3 */

  if (!ntt_can_read(nttunnel))
    return NULL;

  void *rmem = NTM_REMOTE(ntmem);
  void *mem = NTM_LOCAL(ntmem);
  void *mem_cpy = NTM_LOCAL_CPY(ntmem);
  size_t len = NTM_LENGTH(ntmem);

  if (HAS_ERR(ntu_read_memory(rmem, mem, len)))
    return NULL;

  memcpy(mem_cpy, mem, len);
  return mem;
}

static void *
ntm_push_with_tunnel_ex(ntmem_t *ntmem, nttunnel_t *nttunnel, size_t begin, size_t len)
{

#ifdef LOG_LEVEL_3
  LOG_INFO("ntm_push_with_tunnel(ntmem=%p, nttunnel=%p, begin=%d, len=%d)", ntmem, nttunnel, begin, len);
#endif /* ifdef LOG_LEVEL3 */

  if (!ntt_can_write(nttunnel))
    return NULL;

  void *rmem = NTM_REMOTE(ntmem) + begin;
  void *mem = NTM_LOCAL(ntmem) + begin;
  void *mem_cpy = NTM_LOCAL_CPY(ntmem) + begin;

  if (HAS_ERR(ntt_write(nttunnel, rmem, mem, len)))
      return NULL;
  
  memcpy(mem_cpy, mem, len);
  return rmem;
}

void *
ntm_push_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel)
{
  return ntm_push_with_tunnel_ex(ntmem, nttunnel, 0, NTM_LENGTH(ntmem));
}

static void *
ntm_push_with_memset_ex(ntmem_t *ntmem, size_t begin, size_t len)
{

#ifdef LOG_LEVEL_3
  LOG_INFO("ntm_push_with_memset(ntmem=%p, begin=%d, len=%d)", ntmem, begin, len);
#endif /* ifdef LOG_LEVEL3 */

  void *rmem = NTM_REMOTE(ntmem) + begin;
  void *mem = NTM_LOCAL(ntmem) + begin;
  void *mem_cpy = NTM_LOCAL_CPY(ntmem) + begin;

  if (HAS_ERR(ntu_write_with_memset_ex(rmem, mem, len, mem_cpy)))
      return NULL;

  memcpy(mem_cpy, mem, len);
  return rmem;
}

void *
ntm_push_with_memset(ntmem_t *ntmem)
{
  return ntm_push_with_memset_ex(ntmem, 0, NTM_LENGTH(ntmem));
}

size_t
_find_diff_rev(void *mem1, void *mem2, size_t len)
{
  for (size_t i = len - 1; i >= 0; i--) {
    if (((char*) mem1)[i] != ((char*) mem2)[i])
      return i;
  }

  return len;
}

size_t
_find_diff(void *mem1, void *mem2, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    if (((char*) mem1)[i] != ((char*) mem2)[i])
      return i;
  }

  return len;
}

void *
ntm_push(ntmem_t *ntmem, nttunnel_t *nttunnel)
{
  void *rmem = NTM_REMOTE(ntmem);
  bool b = !ntt_can_write(nttunnel);

  if (ntm_is_safe_write(ntmem)) {
    if (b) {
      if (ntm_push_with_memset(ntmem) == NULL)
        return NULL;
    } else
      if (ntm_push_with_tunnel(ntmem, nttunnel) == NULL)
        return NULL;
  } else {
    void *mem = NTM_LOCAL(ntmem);
    void *mem_cpy = NTM_LOCAL_CPY(ntmem);
    
    LOG_INFO("mem(%p) mem_cpy(%p)", mem, mem_cpy);

    size_t sl = _find_diff(mem, mem_cpy, NTM_LENGTH(ntmem));
    if (sl == NTM_LENGTH(ntmem))
      return rmem;

    size_t el = _find_diff_rev(mem, mem_cpy, NTM_LENGTH(ntmem));
    size_t l = el - sl + 1;

    if (b || l < 3) {
      if (ntm_push_with_memset_ex(ntmem, sl, l) == NULL)
        return NULL;
    } else if (ntm_push_with_tunnel_ex(ntmem, nttunnel, sl, l) == NULL)
      return NULL;
  }

  return rmem;
}
