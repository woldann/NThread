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

#include "nttunnel.h"
#include "ntmem.h"
#include "nmem.h"

#include "ntutils.h"

void _ntt_delete_path(nttunnel_fschan_t *fschan)
{
	if (fschan->path != NULL) {
		NFILE_DELETE(fschan->path);
		N_FREE(fschan->path);
	}
}

void *_ntt_create_path(ntmem_t *ntmem, nfile_path_t path)
{
	void *local = NTM_LOCAL(ntmem);
	size_t l = NFILE_PATH_GET_SIZE(path);

	memcpy(local, path, l);
	return local;
}

void *_ntt_create_temp_path(ntmem_t *ntmem)
{
#ifdef _WIN32

	void *local = NTM_LOCAL(ntmem);
	DWORD temp_path_len = GetTempPathW(MAX_PATH, (void *)local);
	if (temp_path_len <= 0)
		return NULL;

	UINT unum = GetTempFileNameW((void *)local, NULL, 0, (void *)local);
	if (unum == 0)
		return NULL;

#endif /* ifdef _WIN32 */

	return local;
}

nerror_t _ntt_init_fschan(nttunnel_t *nttunnel, nttunnel_fschan_t *fschan,
			  nttunnel_fschan_flags_t flags)
{
	ntmem_t *ntmem = nttunnel->ntmem;

	if ((flags & NTTUNNEL_FSCHAN_CREATE_TEMP_PATH) != 0) {
		void *local = _ntt_create_temp_path(ntmem);
		if (local == NULL)
			return GET_ERR(NTTUNNEL_CREATE_TEMP_PATH_ERROR);
	}

#ifdef _WIN32

	static const wchar_t mode_read[] = L"rb";
	static const wchar_t mode_write[] = L"wb";

#endif /* ifdef _WIN32 */

	int8_t mode_len;
	void *mode;
	bool read = (flags & NTTUNNEL_FSCHAN_WRITE_MODE) == 0;
	if (read) {
		mode = (void *)mode_write;
		mode_len = sizeof(mode_write);
	} else {
		mode = (void *)mode_read;
		mode_len = sizeof(mode_read);
	}

	void *local = NTM_LOCAL(ntmem);
	size_t temp_path_size = NFILE_PATH_GET_SIZE(local);
	memcpy((void *)((int8_t *)local + temp_path_size), mode, mode_len);

	bool save_path = (flags & NTTUNNEL_FSCHAN_DONT_SAVE_PATH) == 0;
	if (save_path) {
		fschan->path = N_ALLOC(temp_path_size);
		if (fschan->path == NULL)
			return GET_ERR(NTTUNNEL_ALLOC_ERROR);

		memcpy(fschan->path, local, temp_path_size);
	} else
		fschan->path = NULL;

#ifdef LOG_LEVEL_2
#ifdef _WIN32
	LOG_INFO("ntt_fschan_init(path=%ls, mode=%ls, flags(%02x)", local,
		 (void *)((int8_t *)local + temp_path_size), flags);
#endif /* ifdef _WIN32 */
#endif /* ifdef LOG_LEVEL_2 */

	if (read)
		fschan->local_file = nfile_open_r(local);
	else
		fschan->local_file = nfile_open_w(local);

	if (fschan->local_file == NULL)
		return GET_ERR(NTTUNNEL_NFILE_OPEN_ERROR);

	void *remote = ntm_push_ex(ntmem, nttunnel);
	if (remote == NULL)
		return GET_ERR(NTTUNNEL_NTM_PUSH_ERROR);

	fschan->remote_file =
		ntu_fopen(remote, (void *)((int8_t *)remote + temp_path_size));
	if (fschan->remote_file == NULL)
		return GET_ERR(NTTUNNEL_NTU_FOPEN_ERROR);

	return N_OK;
}

void _ntt_destroy_fschan(nttunnel_fschan_t *fschan)
{
	if (fschan == NULL)
		return;

	if (fschan->remote_file != NULL) {
		ntu_fclose(fschan->remote_file);
		fschan->remote_file = NULL;
	}

	if (fschan->local_file != NULL) {
		NFILE_CLOSE(fschan->local_file);
		fschan->local_file = NULL;
	}

	_ntt_delete_path(fschan);
}

NTHREAD_API bool ntt_can_read(nttunnel_t *nttunnel)
{
	if (nttunnel == NULL)
		return false;

	return nttunnel->read.remote_file != NULL;
}

NTHREAD_API bool ntt_can_write(nttunnel_t *nttunnel)
{
	if (nttunnel == NULL)
		return false;

	return nttunnel->write.remote_file != NULL;
}

NTHREAD_API nerror_t ntt_init_ex(nttunnel_t *nttunnel,
				 nttunnel_fschan_flags_t flags)
{
#ifdef LOG_LEVEL_2
	LOG_INFO("ntt_init_ex(nttunnel=%p, flags=%02x)", nttunnel, flags);
#endif /* ifdef LOG_LEVEL_2 */

	memset(nttunnel, 0, sizeof(nttunnel_t));

	nttunnel->ntmem = ntm_create_with_alloc_ex(
		NFILE_MAX_PATH_SIZE + NTTUNNEL_FSCHAN_MAX_MODE_SIZE);

	if (nttunnel->ntmem == NULL)
		return GET_ERR(NTTUNNEL_NTM_CREATE_WITH_ALLOC_EX_ERROR);

	nttunnel->max_transfer = NTTUNNEL_FSCHAN_CALC_MAX_TRANSFER(flags);

	if (HAS_ERR(_ntt_init_fschan(nttunnel, &nttunnel->write,
				     flags | NTTUNNEL_FSCHAN_WRITE_MODE)))
		goto ntt_init_ex_init_fschan_error;

	if (HAS_ERR(_ntt_init_fschan(nttunnel, &nttunnel->read, flags))) {
ntt_init_ex_init_fschan_error:
		ntt_destroy(nttunnel);
		return GET_ERR(NTTUNNEL_INIT_FSCHAN_ERROR);
	}

	return N_OK;
}

NTHREAD_API nerror_t ntt_init(nttunnel_t *nttunnel)
{
	return ntt_init_ex(nttunnel, NTTUNNEL_FSCHAN_DEFAULT_FLAGS);
}

NTHREAD_API void ntt_destroy(nttunnel_t *nttunnel)
{
	if (nttunnel == NULL)
		return;

	if (nttunnel->ntmem != NULL) {
		ntm_delete_and_free(nttunnel->ntmem);
		nttunnel->ntmem = NULL;
	}

	if (ntt_can_read(nttunnel))
		_ntt_destroy_fschan(&nttunnel->read);

	if (ntt_can_write(nttunnel))
		_ntt_destroy_fschan(&nttunnel->write);
}

nerror_t _ntt_fschan_read(nttunnel_fschan_t *fschan, const void *dest,
			  void *source, size_t length)
{
	size_t len_1 = ntu_fwrite(dest, 1, length, fschan->remote_file);
	if (len_1 != length)
		return GET_ERR(NTTUNNEL_NFILE_READ_ERROR);

	if (ntu_fflush(fschan->remote_file))
		return GET_ERR(NTTUNNEL_NTU_FFLUSH_ERROR);

	size_t len_2 = NFILE_READ(fschan->local_file, source, length);
	if (len_2 != length)
		return GET_ERR(NTTUNNEL_NTU_FWRITE_ERROR);

	return N_OK;
}

nerror_t _ntt_fschan_write(nttunnel_fschan_t *fschan, void *dest,
			   const void *source, size_t length)
{
	size_t len_1 = NFILE_WRITE(fschan->local_file, source, length);
	if (len_1 != length)
		return GET_ERR(NTTUNNEL_NFILE_WRITE_ERROR);

	NFILE_FLUSH(fschan->local_file);

	size_t len_2 = ntu_fread(dest, 1, length, fschan->remote_file);
	if (len_2 != length)
		return GET_ERR(NTTUNNEL_NTU_FREAD_ERROR);

	return N_OK;
}

nerror_t _ntt_fschan_reset(nttunnel_t *nttunnel, nttunnel_fschan_t *fschan,
			   nttunnel_fschan_flags_t flags)
{
	nfile_path_t path = fschan->path;
	bool has_path = path != NULL;
	if ((flags & NTTUNNEL_FSCHAN_CREATE_TEMP_PATH) != 0) {
		nttunnel_fschan_t new_fschan;
		if (HAS_ERR(_ntt_init_fschan(nttunnel, &new_fschan, flags)))
			return GET_ERR(NTTUNNEL_INIT_FSCHAN_ERROR);

		_ntt_destroy_fschan(fschan);
		memcpy(fschan, &new_fschan, sizeof(nttunnel_fschan_t));
	} else {
		if (has_path)
			_ntt_create_path(nttunnel->ntmem, path);
		else {
			flags |= NTTUNNEL_FSCHAN_CREATE_TEMP_PATH;
			flags |= NTTUNNEL_FSCHAN_DONT_SAVE_PATH;
		}

		_ntt_destroy_fschan(fschan);
		if (HAS_ERR(_ntt_init_fschan(nttunnel, fschan, flags)))
			return GET_ERR(NTTUNNEL_INIT_FSCHAN_ERROR);
	}

	return N_OK;
}

NTHREAD_API nerror_t ntt_read(nttunnel_t *nttunnel, const void *dest,
			      void *source, size_t length)
{
	nerror_t ret = _ntt_fschan_read(&nttunnel->read, dest, source, length);
	if (HAS_ERR(ret))
		goto ntt_read_return;

	nttunnel->read_transfer += length;
	if (nttunnel->read_transfer >= nttunnel->max_transfer) {
		nttunnel->read_transfer = 0;
		ret = _ntt_fschan_reset(nttunnel, &nttunnel->read,
					NTTUNNEL_FSCHAN_CREATE_TEMP_PATH);
	}

ntt_read_return:
	return ret;
}

NTHREAD_API nerror_t ntt_write(nttunnel_t *nttunnel, void *dest,
			       const void *source, size_t length)
{
	nerror_t ret =
		_ntt_fschan_write(&nttunnel->write, dest, source, length);
	if (HAS_ERR(ret))
		goto ntt_write_return;

	nttunnel->write_transfer += length;
	if (nttunnel->write_transfer >= nttunnel->max_transfer) {
		nttunnel->write_transfer = 0;
		ret = _ntt_fschan_reset(nttunnel, &nttunnel->write,
					NTTUNNEL_FSCHAN_CREATE_TEMP_PATH |
						NTTUNNEL_FSCHAN_WRITE_MODE);
	}

ntt_write_return:
	return ret;
}
