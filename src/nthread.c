/**
 * Copyright (C) 2024, 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#include "nthread.h"
#include "nerror.h"
#include "log.h"
#include <stdio.h>

#ifdef __WIN32

ntid_t nthread_get_id(nthread_t *nthread)
{
	return GetThreadId(nthread->thread);
}

#endif /* ifdef __WIN32 */

nerror_t nthread_init(nthread_t *nthread, ntid_t thread_id,
		      nthread_reg_offset_t push_reg_offset, void *push_addr,
		      void *sleep_addr)
{
#ifdef LOG_LEVEL_1
	LOG_INFO(
		"nthread_init(thread_id=%ld, push_reg_offset=%ld, push_addr=%p, sleep_addr=%p)",
		thread_id, push_reg_offset, push_addr, sleep_addr);
#endif /* ifdef LOG_LEVEL_1 */

	if (push_addr == NULL || sleep_addr == NULL)
		return NTHREAD_ERROR_INVALID_ARGS;

#ifdef __WIN32

	HANDLE thread = OpenThread(THREAD_ALL_ACCESS, false, thread_id);
	if (thread == NULL)
		return GET_ERR(NTHREAD_OPEN_THREAD_ERROR);

#endif /* ifdef __WIN32 */

	nthread->thread = thread;
	nthread->sleep_addr = sleep_addr;

#ifdef __WIN32

	nthread->o_ctx.ContextFlags = 0;
	nthread->n_ctx.ContextFlags = CONTEXT_ALL;

#endif /* ifdef __WIN32 */

	RET_ERR(nthread_suspend(nthread));

	nerror_t error_helper;

	error_helper = nthread_get_regs(nthread);
	if (HAS_ERR(error_helper)) {
nthread_init_resume_n_exit:
		nthread_resume(nthread);
nthread_init_destroy_n_exit:
		nthread_destroy(nthread);
		return error_helper;
	}

#ifdef __WIN32

	void *rip = NTHREAD_GET_REG(nthread, NTHREAD_RIP);
	void *rsp = NTHREAD_GET_REG(nthread, NTHREAD_RSP);
	void *rvp = NTHREAD_GET_REG(nthread, push_reg_offset);

	NTHREAD_SET_REG(nthread, NTHREAD_RIP, push_addr);
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, rsp + NTHREAD_STACK_ADD);
	NTHREAD_SET_REG(nthread, push_reg_offset, sleep_addr);

#endif /* ifdef __WIN32 */

	error_helper = nthread_set_regs(nthread);
	if (HAS_ERR(error_helper))
		goto nthread_init_resume_n_exit;

	error_helper = nthread_resume(nthread);
	if (HAS_ERR(error_helper))
		goto nthread_init_destroy_n_exit;

	error_helper = nthread_wait(nthread);
	if (HAS_ERR(error_helper))
		goto nthread_init_destroy_n_exit;

#ifdef __WIN32

	memcpy((void *)&nthread->o_ctx, (void *)&nthread->n_ctx,
	       sizeof(CONTEXT));

	NTHREAD_SET_OREG(nthread, NTHREAD_RIP, rip);
	NTHREAD_SET_OREG(nthread, NTHREAD_RSP, rsp);
	NTHREAD_SET_OREG(nthread, push_reg_offset, rvp);

#endif /* ifdef __WIN32 */

#ifdef LOG_LEVEL_2
	LOG_INFO("nthread(%ld) succesfully created", thread_id);
#endif /* ifdef LOG_LEVEL_2 */

	return N_OK;
}

void nthread_destroy(nthread_t *nthread)
{
#ifdef __WIN32

	if (nthread->o_ctx.ContextFlags != 0) {
		memcpy((void *)&nthread->n_ctx, (void *)&nthread->o_ctx,
		       sizeof(CONTEXT));

		nthread_set_regs(nthread);
	}

	if (nthread->thread != NULL)
		CloseHandle(nthread->thread);

#endif /* ifdef __WIN32 */
}

void *nthread_stack_begin(nthread_t *nthread)
{
	return NTHREAD_GET_OREG(nthread, NTHREAD_RSP) + NTHREAD_STACK_ADD;
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
		LOG_WARN("nthread_suspend(nthread_id=%ld) failed", NTHREAD_GET_ID(nthread));
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
	LOG_INFO("nthread_resume(nthread_id=%ld)", NTHREAD_GET_ID(nthread));
#endif /* ifdef LOG_LEVEL_2 */

#ifdef __WIN32

	DWORD count = ResumeThread(nthread->thread);

#ifdef LOG_LEVEL_1

	if (count == (DWORD)(-1)) {
		LOG_WARN("nthread_resume(nthread_id=%ld) failed", NTHREAD_GET_ID(nthread));
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

nerror_t nthread_wait_ex(nthread_t *nthread, uint32_t sleep)
{
	while (true) {
#ifdef __WIN32
		Sleep((DWORD)sleep);
#endif /* ifdef __WIN32 */

		RET_ERR(nthread_get_regs(nthread));

		void *rip = NTHREAD_GET_REG(nthread, NTHREAD_RIP);
		if (rip == nthread->sleep_addr)
			return N_OK;
	}
}

nerror_t nthread_wait(nthread_t *nthread)
{
	return nthread_wait_ex(nthread, NTHREAD_DEFAULT_WAIT_MS);
}

nerror_t nthread_call(nthread_t *nthread, void *fun_addr, void **return_value)
{
#ifdef LOG_LEVEL_3

	LOG_INFO("nthread_call(nthread_id=%ld, fun_addr=%p, return_value=%p)", NTHREAD_GET_ID(nthread),
		 fun_addr, return_value);

#endif /* ifdef LOG_LEVEL_3 */

	NTHREAD_SET_REG(nthread, NTHREAD_RIP, fun_addr);

	void *rsp = nthread_stack_begin(nthread);
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, rsp - sizeof(fun_addr));

	RET_ERR(nthread_set_regs(nthread));
	RET_ERR(nthread_wait(nthread));

	*return_value = NTHREAD_GET_REG(nthread, NTHREAD_RAX);
	return N_OK;
}
