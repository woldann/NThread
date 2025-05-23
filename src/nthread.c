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

#include "nthread.h"
#include "nerror.h"
#include "ntime.h"
#include "log.h"

#ifdef __WIN32

ntid_t nthread_get_id(nthread_t *nthread)
{
	return GetThreadId(nthread->thread);
}

#endif /* ifdef __WIN32 */

static void *nthread_calc_stack(void *rsp)
{
	return rsp + (16 - ((int64_t)(rsp) % 16));
}

static void nthread_copy_ncontext(nthread_t *nthread)
{
	memcpy((void *)&nthread->o_ctx, (void *)&nthread->n_ctx,
	       sizeof(CONTEXT));
}

nerror_t nthread_init_ex(nthread_t *nthread, ntid_t thread_id,
		      nthread_reg_offset_t push_reg_offset, void *push_addr,
		      void *sleep_addr, uint8_t timeout_sec)
{
#ifdef LOG_LEVEL_1
	LOG_INFO(
		"nthread_init(thread_id=%ld, push_reg_offset=%ld, push_addr=%p, sleep_addr=%p)",
		thread_id, push_reg_offset, push_addr, sleep_addr);
#endif /* ifdef LOG_LEVEL_1 */

	if (push_addr == NULL || sleep_addr == NULL)
		return NTHREAD_ERROR_INVALID_ARGS;

#ifdef __WIN32

	HANDLE thread = OpenThread(NTHREAD_ACCESS, false, thread_id);
	if (thread == NULL)
		return GET_ERR(NTHREAD_OPEN_THREAD_ERROR);

#endif /* ifdef __WIN32 */

	nthread->thread = thread;
	nthread->sleep_addr = sleep_addr;
  nthread->timeout = timeout_sec;

#ifdef __WIN32

	nthread->o_ctx.ContextFlags = 0;
	nthread->n_ctx.ContextFlags = CONTEXT_ALL;

#endif /* ifdef __WIN32 */

	RET_ERR(nthread_suspend(nthread));

	nerror_t error_helper = nthread_get_regs(nthread);
	if (HAS_ERR(error_helper))
		goto nthread_init_resume_and_ret;

#ifdef __WIN32

  nthread_copy_ncontext(nthread);

	void *rip = NTHREAD_GET_REG(nthread, NTHREAD_RIP);
	void *rsp = NTHREAD_GET_REG(nthread, NTHREAD_RSP);
	void *rvp = NTHREAD_GET_REG(nthread, push_reg_offset);

	nthread->n_ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

	NTHREAD_SET_REG(nthread, NTHREAD_RIP, push_addr);

	void *new_rsp = nthread_calc_stack(rsp + NTHREAD_STACK_ADD);
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, new_rsp);
	NTHREAD_SET_REG(nthread, push_reg_offset, sleep_addr);

#endif /* ifdef __WIN32 */

	error_helper = nthread_set_regs(nthread);
	if (HAS_ERR(error_helper)) {
nthread_init_resume_and_ret:
		nthread_resume(nthread);
nthread_init_destroy_and_ret:
		nthread_destroy(nthread);
		return error_helper;
  }

	error_helper = nthread_resume(nthread);
	if (HAS_ERR(error_helper))
		goto nthread_init_destroy_and_ret;

	error_helper = nthread_wait(nthread);
	if (HAS_ERR(error_helper)) {
		goto nthread_init_destroy_and_ret;
  }
	
  nthread_copy_ncontext(nthread);

	NTHREAD_SET_OREG(nthread, NTHREAD_RIP, rip);
	NTHREAD_SET_OREG(nthread, NTHREAD_RSP, rsp);
	NTHREAD_SET_OREG(nthread, push_reg_offset, rvp);

#ifdef LOG_LEVEL_2
	LOG_INFO("nthread(%ld) succesfully created", thread_id);
#endif /* ifdef LOG_LEVEL_2 */

	return N_OK;
}

nerror_t nthread_init(nthread_t *nthread, ntid_t thread_id,
		      nthread_reg_offset_t push_reg_offset, void *push_addr,
		      void *sleep_addr)
{
  return nthread_init_ex(nthread, thread_id, push_reg_offset, push_addr, sleep_addr, NTHREAD_DEFAULT_TIMEOUT);
}

void nthread_destroy(nthread_t *nthread)
{
#ifdef __WIN32

	if (nthread->o_ctx.ContextFlags != 0) {
		memcpy((void *)&nthread->n_ctx, (void *)&nthread->o_ctx,
		       sizeof(CONTEXT));

		nthread_set_regs(nthread);
	}

	if (nthread->thread != NULL) {
		CloseHandle(nthread->thread);
    nthread->thread = NULL;
  }

#endif /* ifdef __WIN32 */
}

void *nthread_stack_begin(nthread_t *nthread)
{
	void *rsp = NTHREAD_GET_OREG(nthread, NTHREAD_RSP) + NTHREAD_STACK_ADD;
	return nthread_calc_stack(rsp);
}

nerror_t nthread_suspend(nthread_t *nthread)
{
#ifdef LOG_LEVEL_2
	LOG_INFO("nthread_suspend(nthread_id=%ld)", NTHREAD_GET_ID(nthread));
#endif /* ifdef LOG_LEVEL_2 */

#ifdef __WIN32

	DWORD count = SuspendThread(nthread->thread);

#ifdef LOG_LEVEL_1

	if (count == (DWORD)(-1)) {
		LOG_WARN("nthread_suspend(nthread_id=%ld) failed",
			 NTHREAD_GET_ID(nthread));

		return GET_ERR(NTHREAD_SUSPEND_ERROR);
	}

#else /* ifndef LOG_LEVEL_1 */

	if (count == (DWORD)(-1))
		return GET_ERR(NTHREAD_SUSPEND_ERROR);

#endif /* infdef LOG_LEVEL_1 */
#endif /* ifdef __WIN32 */

	return N_OK;
}

nerror_t nthread_resume(nthread_t *nthread)
{
#ifdef LOG_LEVEL_2
	LOG_INFO(
		"nthread_resume(nthread_id=%ld) called. If this hangs, see: https://github.com/woldann/nthread/wiki/nthread_resume-troubleshooting",
		NTHREAD_GET_ID(nthread));
#endif /* ifdef LOG_LEVEL_2 */

#ifdef __WIN32

	DWORD count = ResumeThread(nthread->thread);

#ifdef LOG_LEVEL_1

	if (count == (DWORD)(-1)) {
		LOG_WARN("nthread_resume(nthread_id=%ld) failed",
			 NTHREAD_GET_ID(nthread));

		return GET_ERR(NTHREAD_RESUME_ERROR);
	}

#else /* ifndef LOG_LEVEL_1 */

	if (count == (DWORD)(-1))
		return GET_ERR(NTHREAD_RESUME_ERROR);

#endif /* infdef LOG_LEVEL_1 */
#endif /* ifdef __WIN32 */

	return N_OK;
}

nerror_t nthread_get_regs(nthread_t *nthread)
{
#ifdef __WIN32

	if (!GetThreadContext(nthread->thread, &nthread->n_ctx))
		return GET_ERR(NTHREAD_GET_CONTEXT_ERROR);

#endif /* ifdef __WIN32 */

	return N_OK;
}

nerror_t nthread_set_regs(nthread_t *nthread)
{
#ifdef __WIN32

	if (!SetThreadContext(nthread->thread, &nthread->n_ctx))
		return GET_ERR(NTHREAD_SET_CONTEXT_ERROR);

#endif /* ifdef __WIN32 */

	return N_OK;
}

void nthread_set_timeout(nthread_t *nthread, uint8_t timeout_sec)
{ 
  nthread->timeout = timeout_sec;
}

nerror_t nthread_wait_ex(nthread_t *nthread, uint32_t sleep)
{
  ntime_t end; 
  uint32_t timeout_sec = nthread->timeout;
  if (timeout_sec != 0) {
    end = ntime_get_unix() + timeout_sec;
    uint32_t timeout_ms = timeout_sec * 1000; 
    if (sleep >= timeout_ms)
      sleep = timeout_ms + 1;
  }
  else
    end = 0;

	while (true) {
#ifdef __WIN32
		Sleep((DWORD)sleep);
#endif /* ifdef __WIN32 */

		RET_ERR(nthread_get_regs(nthread));

		void *rip = NTHREAD_GET_REG(nthread, NTHREAD_RIP);
		if (rip == nthread->sleep_addr)
			return N_OK;

    if (end > 0) {
      ntime_t cur = ntime_get_unix();
      if (cur >= end)
        return GET_ERR(NTHREAD_TIMEOUT_ERROR);
    }
	}
}

nerror_t nthread_wait(nthread_t *nthread)
{
	return nthread_wait_ex(nthread, NTHREAD_DEFAULT_WAIT_MS);
}

nerror_t nthread_call(nthread_t *nthread, void *fun_addr, void **return_value)
{
#ifdef LOG_LEVEL_3

	LOG_INFO("nthread_call(nthread_id=%ld, fun_addr=%p, return_value=%p)",
		 NTHREAD_GET_ID(nthread), fun_addr, return_value);

#endif /* ifdef LOG_LEVEL_3 */

	NTHREAD_SET_REG(nthread, NTHREAD_RIP, fun_addr);

	void *rsp = nthread_stack_begin(nthread);
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, rsp - sizeof(fun_addr));

	RET_ERR(nthread_set_regs(nthread));
	RET_ERR(nthread_wait(nthread));

	*return_value = NTHREAD_GET_REG(nthread, NTHREAD_RAX);
	return N_OK;
}
