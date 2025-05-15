/*
 * Copyright (C) 2024, 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

#ifndef __NTHREAD_H__
#define __NTHREAD_H__

#include "neptune.h"
#include "nerror.h"

#if !(defined(__x86_64__) || defined(__amd64__) || defined(__LP64__) || \
      defined(_LP64))
#error "NThread only works on x86_64 systems."
#endif

#if !(defined(__WIN32) || defined(__linux__))
#error "NThread unsupported os."
#endif // OS Check

#ifdef __WIN32

#include <windows.h>

typedef int16_t nthread_reg_offset_t;

#define WINDOWS_RAX_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rax))
#define WINDOWS_RBX_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rbx))
#define WINDOWS_RCX_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rcx))
#define WINDOWS_RDX_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rdx))
#define WINDOWS_RSI_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rsi))
#define WINDOWS_RDI_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rdi))
#define WINDOWS_R8_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R8))
#define WINDOWS_R9_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R9))
#define WINDOWS_R10_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R10))
#define WINDOWS_R11_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R11))
#define WINDOWS_R12_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R12))
#define WINDOWS_R13_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R13))
#define WINDOWS_R14_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R14))
#define WINDOWS_R15_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, R15))
#define WINDOWS_RIP_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rip))
#define WINDOWS_RSP_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rsp))
#define WINDOWS_RBP_OFFSET ((nthread_reg_offset_t)offsetof(CONTEXT, Rbp))

#define WINDOWS_BEST_PUSH_REG WINDOWS_RBP_OFFSET
#define NTHREAD_BEST_PUSH_REG WINDOWS_BEST_PUSH_REG

#define NTHREAD_RAX WINDOWS_RAX_OFFSET
#define NTHREAD_RBX WINDOWS_RBX_OFFSET
#define NTHREAD_RCX WINDOWS_RCX_OFFSET
#define NTHREAD_RDX WINDOWS_RDX_OFFSET
#define NTHREAD_RSI WINDOWS_RSI_OFFSET
#define NTHREAD_RDI WINDOWS_RDI_OFFSET
#define NTHREAD_R8 WINDOWS_R8_OFFSET
#define NTHREAD_R9 WINDOWS_R9_OFFSET
#define NTHREAD_R10 WINDOWS_R10_OFFSET
#define NTHREAD_R11 WINDOWS_R11_OFFSET
#define NTHREAD_R12 WINDOWS_R12_OFFSET
#define NTHREAD_R13 WINDOWS_R13_OFFSET
#define NTHREAD_R14 WINDOWS_R14_OFFSET
#define NTHREAD_R15 WINDOWS_R15_OFFSET
#define NTHREAD_RIP WINDOWS_RIP_OFFSET
#define NTHREAD_RSP WINDOWS_RSP_OFFSET
#define NTHREAD_RBP WINDOWS_RBP_OFFSET

#define NTHREAD_ACCESS THREAD_ALL_ACCESS

typedef DWORD ntid_t;
typedef HANDLE nthread_handle_t;
typedef CONTEXT nthread_regs_t;

#else // !__WIN32

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>

typedef pid_t ntid_t;
typedef ntid_t nthread_handle_t;
typedef struct user_regs_struct nthread_regs_t;

#define NTHREAD_GET_ID(nthread) (((nthread_t *)nthread)->thread)

#endif // !__WIN32

#include <stdbool.h>
#include <stdint.h>

#define NTHREAD_DEFAULT_WAIT_MS 0x00

#define NTHREAD_ERROR 0x4760
#define NTHREAD_SUSPEND_ERROR 0x4761
#define NTHREAD_RESUME_ERROR 0x4762
#define NTHREAD_OPEN_THREAD_ERROR 0x4763
#define NTHREAD_GET_CONTEXT_ERROR 0x4764
#define NTHREAD_SET_CONTEXT_ERROR 0x4765
#define NTHREAD_ERROR_INVALID_ARGS 0x4766
#define NTHREAD_ERROR_E NTHREAD_ERROR_INVALID_ARGS

#define NTHREAD_STACK_ADD (-8192)

typedef struct {
	nthread_handle_t thread;
	void *sleep_addr;

	nthread_regs_t n_ctx;
	nthread_regs_t o_ctx;
} nthread_t;

#ifdef __WIN32

ntid_t nthread_get_id(nthread_t *nthread);

#define NTHREAD_GET_ID(nthread) nthread_get_id(nthread)

#endif // __WIN32

#define NTHREAD_GET_REG(nthread, reg) \
	(((void **)(((void *)&nthread->n_ctx) + reg))[0])

#define NTHREAD_SET_REG(nthread, reg, set) \
	(((void **)(((void *)&nthread->n_ctx) + reg))[0] = (void *)set)

#define NTHREAD_GET_OREG(nthread, reg) \
	(((void **)(((void *)&nthread->o_ctx) + reg))[0])

#define NTHREAD_SET_OREG(nthread, reg, set) \
	(((void **)(((void *)&nthread->o_ctx) + reg))[0] = (void *)set)

nerror_t nthread_init(nthread_t *nthread, ntid_t ntid,
		      nthread_reg_offset_t push_reg_offset, void *push_addr,
		      void *sleep_addr);

void nthread_destroy(nthread_t *nthread);

void *nthread_stack_begin(nthread_t *nthread);

nerror_t nthread_suspend(nthread_t *nthread);

nerror_t nthread_resume(nthread_t *nthread);

nerror_t nthread_fetch_regs(nthread_t *nthread);

nerror_t nthread_update_regs(nthread_t *nthread);

nerror_t nthread_wait_ex(nthread_t *nthread, uint32_t sleep);

nerror_t nthread_wait(nthread_t *nthread);

nerror_t nthread_call(nthread_t *nthread, void *function_address,
		      void **return_value);

#endif // !__NSHELL_H__
