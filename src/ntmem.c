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

#include "ntmem.h"
#include "nttunnel.h"
#include "nmem.h"

NTHREAD_API void ntm_enable_safe_write(ntmem_t *ntmem)
{
	ntmem->flags |= NTMEM_SAFE_WRITE;
}

NTHREAD_API void ntm_disable_safe_write(ntmem_t *ntmem)
{
	ntmem->flags &= ~(NTMEM_SAFE_WRITE);
}

NTHREAD_API bool ntm_is_safe_write(ntmem_t *ntmem)
{
	return (ntmem->flags & NTMEM_SAFE_WRITE) != 0;
}

NTHREAD_API void *ntm_reset_locals(ntmem_t *ntmem)
{
	void *local = NTM_LOCAL(ntmem);
	memset(local, 0, NTM_CALC_LOCALS_SIZE(NTM_LENGTH(ntmem)));
	return local;
}

NTHREAD_API void *ntm_reset_remote_ex(ntmem_t *ntmem, size_t length)
{
	void *remote = NTM_REMOTE(ntmem);
	if (ntu_memset(remote, 0, length) == NULL)
		return NULL;

	return remote;
}

NTHREAD_API void *ntm_reset_remote(ntmem_t *ntmem)
{
	return ntm_reset_remote_ex(ntmem, NTM_LENGTH(ntmem));
}

NTHREAD_API nerror_t ntm_reset(ntmem_t *ntmem)
{
	if (ntm_reset_remote(ntmem) == NULL)
		return GET_ERR(NTMEM_NTM_RESET_REMOTE_ERROR);

	ntm_reset_locals(ntmem);
	return N_OK;
}

NTHREAD_API void *ntm_alloc_remote(ntmem_t *ntmem)
{
	size_t len = NTM_LENGTH(ntmem);

	NTM_SET_REMOTE(ntmem, ntu_malloc(len));
	return NTM_REMOTE(ntmem);
}

NTHREAD_API void ntm_free_remote(ntmem_t *ntmem)
{
	if (NTM_REMOTE(ntmem) != NULL) {
		ntu_free(NTM_REMOTE(ntmem));
		NTM_SET_REMOTE(ntmem, NULL);
	}
}

NTHREAD_API void *ntm_alloc_remote_and_reset(ntmem_t *ntmem)
{
	void *remote = ntm_alloc_remote(ntmem);
	if (remote == NULL)
		return NULL;

	if (HAS_ERR(ntm_reset(ntmem))) {
		ntm_free_remote(ntmem);
		return NULL;
	}

	return remote;
}

NTHREAD_API ntmem_t *ntm_create_ex(size_t length)
{
	ntmem_t *ntmem = N_ALLOC(NTM_CALC_STRUCT_SIZE(length));
	if (ntmem == NULL)
		return NULL;

	NTM_SET_LENGTH(ntmem, length);
	return ntmem;
}

NTHREAD_API ntmem_t *ntm_create()
{
	return ntm_create_ex(NTMEM_DEFAULT_LENGTH);
}

NTHREAD_API ntmem_t *ntm_create_with_alloc_ex(size_t length)
{
	ntmem_t *ntmem = ntm_create_ex(length);
	if (ntmem == NULL)
		return NULL;

	if (ntm_alloc_remote_and_reset(ntmem) == NULL) {
		ntm_delete_and_free(ntmem);
		return NULL;
	}
	return ntmem;
}

NTHREAD_API ntmem_t *ntm_create_with_alloc()
{
	return ntm_create_with_alloc_ex(NTMEM_DEFAULT_LENGTH);
}

NTHREAD_API ntmem_t *ntm_create_from_remote(void *remote, size_t length)
{
	ntmem_t *ntmem = ntm_create_ex(length);
	if (ntmem == NULL)
		return NULL;

	NTM_SET_REMOTE(ntmem, remote);
	if (HAS_ERR(ntm_reset(ntmem))) {
		ntm_delete_and_detach(ntmem);
		return NULL;
	}

	return ntmem;
}

NTHREAD_API void ntm_delete(ntmem_t *ntmem)
{
	N_FREE(ntmem);
}

NTHREAD_API void ntm_delete_and_free(ntmem_t *ntmem)
{
	ntm_free_remote(ntmem);
	ntm_delete(ntmem);
}

NTHREAD_API void *ntm_delete_and_detach(ntmem_t *ntmem)
{
	void *remote = NTM_REMOTE(ntmem);
	ntm_delete(ntmem);
	return remote;
}

NTHREAD_API void *ntm_pull_with_tunnel_ex(ntmem_t *ntmem, nttunnel_t *nttunnel,
					  size_t len)
{
#ifdef LOG_LEVEL_3
	LOG_INFO("ntm_pull(ntmem=%p, nttunnel=%p)", ntmem, nttunnel);
#endif /* ifdef LOG_LEVEL3 */

	if (!ntt_can_read(nttunnel))
		return NULL;

	void *remote = NTM_REMOTE(ntmem);
	void *local = NTM_LOCAL(ntmem);
	void *local_cpy = NTM_LOCAL_CPY(ntmem);

	if (HAS_ERR(ntu_read_memory(remote, local, len)))
		return NULL;

	memcpy(local_cpy, local, len);
	return local;
}

NTHREAD_API void *ntm_pull_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel)
{
	return ntm_pull_with_tunnel_ex(ntmem, nttunnel, NTM_LENGTH(ntmem));
}

static void *ntm_push_with_tunnel_ex(ntmem_t *ntmem, nttunnel_t *nttunnel,
				     size_t begin, size_t len)
{
#ifdef LOG_LEVEL_3
	LOG_INFO(
		"ntm_push_with_tunnel(ntmem=%p, nttunnel=%p, begin=%d, len=%d)",
		ntmem, nttunnel, begin, len);
#endif /* ifdef LOG_LEVEL3 */

	if (!ntt_can_write(nttunnel))
		return NULL;

	void *remote = (void *)((int8_t *)NTM_REMOTE(ntmem) + begin);
	void *local = (void *)((int8_t *)NTM_LOCAL(ntmem) + begin);
	void *local_cpy = (void *)((int8_t *)NTM_LOCAL_CPY(ntmem) + begin);

	if (HAS_ERR(ntt_write(nttunnel, remote, local, len)))
		return NULL;

	memcpy(local_cpy, local, len);
	return remote;
}

NTHREAD_API void *ntm_push_with_tunnel(ntmem_t *ntmem, nttunnel_t *nttunnel)
{
	return ntm_push_with_tunnel_ex(ntmem, nttunnel, 0, NTM_LENGTH(ntmem));
}

static void *ntm_push_with_memset_ex(ntmem_t *ntmem, size_t begin, size_t len)
{
#ifdef LOG_LEVEL_3
	LOG_INFO("ntm_push_with_memset(ntmem=%p, begin=%d, len=%d)", ntmem,
		 begin, len);
#endif /* ifdef LOG_LEVEL3 */

	void *remote = (void *)((int8_t *)NTM_REMOTE(ntmem) + begin);
	void *local = (void *)((int8_t *)NTM_LOCAL(ntmem) + begin);
	void *local_cpy = (void *)((int8_t *)NTM_LOCAL_CPY(ntmem) + begin);

	if (ntm_is_safe_write(ntmem)) {
		if (HAS_ERR(ntu_write_with_memset(remote, local, len)))
			return NULL;
	} else {
		if (HAS_ERR(ntu_write_with_memset_dest(remote, local, len,
						       local_cpy)))
			return NULL;
	}

	memcpy(local_cpy, local, len);
	return remote;
}

NTHREAD_API void *ntm_push_with_memset(ntmem_t *ntmem)
{
	return ntm_push_with_memset_ex(ntmem, 0, NTM_LENGTH(ntmem));
}

size_t _find_diff_rev(void *mem1, void *mem2, size_t len)
{
	if (len == 0)
		return 0;

	size_t i = len - 1;
	while (true) {
		if (((char *)mem1)[i] != ((char *)mem2)[i])
			return i;

		if (i == 0)
			break;

		i--;
	}

	return len;
}

size_t _find_diff(void *mem1, void *mem2, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (((char *)mem1)[i] != ((char *)mem2)[i])
			return i;
	}

	return len;
}

NTHREAD_API void *ntm_push_ex(ntmem_t *ntmem, nttunnel_t *nttunnel)
{
	void *remote = NTM_REMOTE(ntmem);
	bool b = !ntt_can_write(nttunnel);

	if (ntm_is_safe_write(ntmem)) {
		if (b) {
			if (ntm_push_with_memset(ntmem) == NULL)
				return NULL;
		} else if (ntm_push_with_tunnel(ntmem, nttunnel) == NULL)
			return NULL;
	} else {
		void *local = NTM_LOCAL(ntmem);
		void *local_cpy = NTM_LOCAL_CPY(ntmem);

		size_t sl = _find_diff(local, local_cpy, NTM_LENGTH(ntmem));
		if (sl == NTM_LENGTH(ntmem))
			return remote;

		size_t el = _find_diff_rev(local, local_cpy, NTM_LENGTH(ntmem));
		size_t l = el - sl + 1;

		if (b || l < 3) {
			if (ntm_push_with_memset_ex(ntmem, sl, l) == NULL)
				return NULL;
		} else if (ntm_push_with_tunnel_ex(ntmem, nttunnel, sl, l) ==
			   NULL)
			return NULL;
	}

	return remote;
}

NTHREAD_API void *ntm_push(ntmem_t *ntmem)
{
	nttunnel_t *nttunnel = ntu_nttunnel();
	return ntm_push_ex(ntmem, nttunnel);
}
