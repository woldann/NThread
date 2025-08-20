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
 * @file ntucc.h
 * @brief Calling convention helper macros for ntutils.
 *
 * Provides simplified and more readable macro definitions to select and apply
 * calling conventions when working with ntutils-related function calls.
 */

#ifndef __NTUCC_H__
#define __NTUCC_H__

#include "neptune.h"

typedef int64_t ntucc_t;

#define NTUCC_RBX NTHREAD_RBX_INDEX
#define NTUCC_RCX NTHREAD_RCX_INDEX
#define NTUCC_RDX NTHREAD_RDX_INDEX
#define NTUCC_RDI NTHREAD_RDI_INDEX
#define NTUCC_RSI NTHREAD_RSI_INDEX
#define NTUCC_RSP NTHREAD_RSP_INDEX
#define NTUCC_RBP NTHREAD_RSP_INDEX
#define NTUCC_R8 NTHREAD_R8_INDEX
#define NTUCC_R9 NTHREAD_R9_INDEX
#define NTUCC_R10 NTHREAD_R10_INDEX
#define NTUCC_R11 NTHREAD_R11_INDEX
#define NTUCC_R12 NTHREAD_R12_INDEX
#define NTUCC_R13 NTHREAD_R13_INDEX
#define NTUCC_R14 NTHREAD_R14_INDEX
#define NTUCC_R15 NTHREAD_R15_INDEX

#define NTUCC_CALC_ARG(reg_index, arg_pos) \
	(((int64_t)(reg_index)) << (((arg_pos) * 4) + 0x20))

#define NTUCC_CREATE_ARG_1(i1) (NTUCC_CALC_ARG(i1, 0))
#define NTUCC_CREATE_ARG_2(i1, i2) \
	(NTUCC_CREATE_ARG_1(i1) + NTUCC_CALC_ARG(i2, 1))

#define NTUCC_CREATE_ARG_3(i1, i2, i3) \
	(NTUCC_CREATE_ARG_2(i1, i2) + NTUCC_CALC_ARG(i3, 2))

#define NTUCC_CREATE_ARG_4(i1, i2, i3, i4) \
	(NTUCC_CREATE_ARG_3(i1, i2, i3) + NTUCC_CALC_ARG(i4, 3))

#define NTUCC_CREATE_ARG_5(i1, i2, i3, i4, i5) \
	(NTUCC_CREATE_ARG_4(i1, i2, i3, i4) + NTUCC_CALC_ARG(i5, 4))

#define NTUCC_CREATE_ARG_6(i1, i2, i3, i4, i5, i6) \
	(NTUCC_CREATE_ARG_5(i1, i2, i3, i4, i5) + NTUCC_CALC_ARG(i6, 5))

#define NTUCC_CREATE_ARG_7(i1, i2, i3, i4, i5, i6, i7) \
	(NTUCC_CREATE_ARG_6(i1, i2, i3, i4, i5, i6) + NTUCC_CALC_ARG(i7, 6))

#define NTUCC_CREATE_ARG_8(i1, i2, i3, i4, i5, i6, i7, i8) \
	(NTUCC_CREATE_ARG_6(i1, i2, i3, i4, i5, i6, i7) + NTUCC_CALC_ARG(i8, 7))

#define NTUCC_GET_ARG_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define NTUCC_CREATE_ARG_MASK(...)                                  \
	NTUCC_GET_ARG_MACRO(__VA_ARGS__, NTUCC_CREATE_ARG_8,        \
			    NTUCC_CREATE_ARG_7, NTUCC_CREATE_ARG_6, \
			    NTUCC_CREATE_ARG_5, NTUCC_CREATE_ARG_4, \
			    NTUCC_CREATE_ARG_3, NTUCC_CREATE_ARG_2, \
			    NTUCC_CREATE_ARG_1)(__VA_ARGS__)

#define NTUCC_GET_ARG(cc, arg_pos) \
	(((int8_t)(cc >> (((arg_pos) * 4) + 0x20))) & 0x0F)

#define NTUCC_REVERSE_OP (0x10000)
#define NTUCC_AUTO_CLEAN (0x20000)

#define NTUCC_GET_STACK_ADD(cc) ((uint16_t)(cc & 0xFFFF))

#define NTUCC_WINDOWS_X64                                                  \
	(NTUCC_CREATE_ARG_MASK(NTUCC_RCX, NTUCC_RDX, NTUCC_R8, NTUCC_R9) | \
	 NTUCC_AUTO_CLEAN + sizeof(DWORD64) * 4)

#ifdef NTUCC_WINDOWS_X64

#define NTUCC_WINDOWS_X64_PASS_RCX                               \
	((NTUCC_CREATE_ARG_MASK(NTUCC_RDX, NTUCC_R8, NTUCC_R9) | \
	  NTUCC_AUTO_CLEAN) +                                    \
	 sizeof(DWORD64) * 4)

#endif // NTUCC_WINDOWS_X64

#define NTUCC_MAX_REGARG_COUNT 4

#define NTUCC_GET_REGARG_COUNT(ntu_cc) (ntu_cc & NTUCC_HAS_REGARG_MASK)
#define NTUCC_HAS_REGARG(ntu_cc) ((ntu_cc & NTUCC_HAS_REGARG_MASK) != 0)

#ifdef _WIN32
#define NTUCC_DEFAULT NTUCC_WINDOWS_X64
#endif // _WIN32

#endif // !__NTUCC_H__
