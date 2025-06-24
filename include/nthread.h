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

/**
 * @file nthread.h
 * @brief Stealth thread manipulation library for x64.
 *
 * NThread provides a safe and stealthy way to call functions inside a target process
 * using its own existing threads. It avoids traditional remote memory allocations
 * or shellcode injections, using only safe system APIs like OpenThread,
 * GetThreadContext, SetThreadContext.
 */

#ifndef __NTHREAD_H__
#define __NTHREAD_H__

#include "neptune.h"
#include "nerror.h"

#if !(defined(__x86_64__) || defined(__amd64__) || defined(__LP64__) || \
      defined(_LP64) || defined(_WIN64))
#error "NThread only works on x86_64 systems."
#endif

#if !(defined(_WIN32) || defined(__linux__))
#error "NThread unsupported os."
#endif // OS Check

#ifdef _WIN32

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

#define NTHREAD_RAX_INDEX 0x00
#define NTHREAD_RCX_INDEX 0x01
#define NTHREAD_RDX_INDEX 0x02
#define NTHREAD_RBX_INDEX 0x03
#define NTHREAD_RSP_INDEX 0x04
#define NTHREAD_RBP_INDEX 0x05
#define NTHREAD_RSI_INDEX 0x06
#define NTHREAD_RDI_INDEX 0x07
#define NTHREAD_R8_INDEX 0x08
#define NTHREAD_R9_INDEX 0x09
#define NTHREAD_R10_INDEX 0x0A
#define NTHREAD_R11_INDEX 0x0B
#define NTHREAD_R12_INDEX 0x0C
#define NTHREAD_R13_INDEX 0x0D
#define NTHREAD_R14_INDEX 0x0E
#define NTHREAD_R15_INDEX 0x0F
#define NTHREAD_RIP_INDEX 0x10

typedef uint8_t nthread_flags_t;

#define NTHREAD_FLAG_DONT_SUSPEND 0x10
#define NTHREAD_FLAG_DONT_RESUME 0x20
#define NTHREAD_FLAG_DISABLE_GET_ID 0x40

#define NTHREAD_REG_INDEX_TO_OFFSET(reg_index) \
	((nthread_reg_offset_t)(NTHREAD_RAX + ((sizeof(DWORD64)) * reg_index)))

#define NTHREAD_ACCESS                                                    \
	THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | \
		THREAD_QUERY_INFORMATION

typedef DWORD ntid_t;
typedef HANDLE nthread_handle_t;
typedef CONTEXT nthread_regs_t;

#else // !_WIN32

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>

typedef pid_t ntid_t;
typedef ntid_t nthread_handle_t;
typedef struct user_regs_struct nthread_regs_t;

#define NTHREAD_GET_ID(nthread) (((nthread_t *)nthread)->thread)

#endif // !_WIN32

#define NTHREAD_DEFAULT_WAIT_MS 0x00
#define NTHREAD_DEFAULT_TIMEOUT 0x00

#define NTHREAD_ERROR 0x4760

#define NTHREAD_SUSPEND_ERROR 0x4761
#define NTHREAD_RESUME_ERROR 0x4762
#define NTHREAD_OPEN_THREAD_ERROR 0x4763
#define NTHREAD_GET_CONTEXT_ERROR 0x4764
#define NTHREAD_SET_CONTEXT_ERROR 0x4765
#define NTHREAD_ERROR_INVALID_ARGS 0x4766
#define NTHREAD_TIMEOUT_ERROR 0x4767

#define NTHREAD_ERROR_E NTHREAD_ERROR_INVALID_ARGS

#define NTHREAD_STACK_ADD (-8192)

typedef struct {
	nthread_handle_t thread;
	void *sleep_addr;
	uint8_t timeout;

	nthread_regs_t n_ctx;
	nthread_regs_t o_ctx;
} nthread_t;

#ifdef _WIN32

#ifndef NTHREAD_API
#define NTHREAD_API NEPTUNE_API
#endif // !NTHREAD_API

#define NTHREAD_IS_VALID(nthread) ((nthread)->thread != NULL)
#define NTHREAD_SET_INVALID(nthread) ((nthread)->thread = NULL)

NTHREAD_API ntid_t nthread_get_id(nthread_t *nthread);

#define NTHREAD_GET_ID(nthread) nthread_get_id(nthread)

#else // !_WIN32

#define NTHREAD_IS_VALID(nthread) ((nthread)->thread != 0)
#define NTHREAD_SET_INVALID(nthread) ((nthread)->thread = 0)

#define NTHREAD_GET_ID(nthread) ((nthread)->thread)

#endif // !_WIN32

#define NTHREAD_GET_REG(nthread, reg) \
	(((void **)(((int8_t *)&(nthread)->n_ctx) + reg))[0])

#define NTHREAD_SET_REG(nthread, reg, set) \
	(((void **)(((int8_t *)&(nthread)->n_ctx) + (reg)))[0] = (void *)(set))

#define NTHREAD_GET_OREG(nthread, reg) \
	(((void **)(((int8_t *)&(nthread)->o_ctx) + reg))[0])

#define NTHREAD_SET_OREG(nthread, reg, set) \
	(((void **)(((int8_t *)&(nthread)->o_ctx) + (reg)))[0] = (void *)(set))

NTHREAD_API bool nthread_is_waiting(nthread_t *nthread);

NTHREAD_API nerror_t nthread_init_ex(nthread_t *nthread, ntid_t ntid,
				     nthread_reg_offset_t push_reg_offset,
				     void *push_addr, void *sleep_addr,
				     nthread_flags_t flags);

NTHREAD_API nerror_t nthread_init(nthread_t *nthread, ntid_t ntid,
				  nthread_reg_offset_t push_reg_offset,
				  void *push_addr, void *sleep_addr);

/**
 * @brief Release resources and restore context related to an NThread instance.
 *
 * Should be called after operations are completed to clean up state.
 *
 * @param nthread Pointer to the NThread structure to destroy.
 */
NTHREAD_API void nthread_destroy(nthread_t *nthread);

/**
 * @brief Retrieve the base address of the thread's stack.
 *
 * @param nthread Pointer to the NThread structure.
 * @return Pointer to the beginning of the thread's stack.
 */
NTHREAD_API void *nthread_stack_begin(nthread_t *nthread);

/**
 * @brief Suspend execution of the target thread.
 *
 * @param nthread Pointer to the NThread structure.
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t nthread_suspend(nthread_t *nthread);

/**
 * @brief Resume execution of a previously suspended thread.
 *
 * @param nthread Pointer to the NThread structure.
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t nthread_resume(nthread_t *nthread);

/**
 * @brief Read the current CPU context (registers) of the target thread.
 *
 * @param nthread Pointer to the NThread structure.
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t nthread_get_regs(nthread_t *nthread);

/**
 * @brief Set the CPU context (registers) of the target thread.
 *
 * Applies previously modified or constructed context to the thread.
 *
 * @param nthread Pointer to the NThread structure.
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t nthread_set_regs(nthread_t *nthread);

NTHREAD_API void nthread_set_timeout(nthread_t *nthread, uint8_t timeout_sec);

/**
 * @brief Wait for the thread to return from a function call, with timeout control.
 *
 * Repeatedly checks if the thread has returned from execution within the specified time.
 *
 * @param nthread Pointer to the NThread structure.
 * @param sleep Timeout in milliseconds between each status check.
 * @return Error code indicating success, timeout, or failure.
 */
NTHREAD_API nerror_t nthread_wait_ex(nthread_t *nthread, uint32_t sleep);

/**
 * @brief Wait indefinitely until the thread returns from a function call.
 *
 * @param nthread Pointer to the NThread structure.
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t nthread_wait(nthread_t *nthread);

/**
 * @brief Execute a function inside the target process using the hijacked thread.
 *
 * This manipulates the thread's instruction pointer to call the provided function address.
 *
 * @param nthread Pointer to the NThread structure.
 * @param function_address Address of the target function to call.
 * @param return_value Pointer to store the return value of the function, if any.
 *
 * @return Error code indicating success or failure.
 */
NTHREAD_API nerror_t nthread_call(nthread_t *nthread, void *function_address,
				  void **return_value);

#endif // !__NSHELL_H__
