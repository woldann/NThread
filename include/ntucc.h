/**
 * Copyright (C) 2024, 2025 Serkan Aksoy
 * All rights reserved.
 *
 * This file is part of the NThread project.
 * It may not be copied or distributed without permission.
 */

/**
 * @file ntucc.h
 * @brief Calling convention helper macros for ntutils.
 *
 * Provides simplified and more readable macro definitions to select and apply
 * calling conventions when working with ntutils-related function calls.
 */

#ifndef __NTU_CC__
#define __NTU_CC__

#include "neptune.h"

#define NTUCC_1_REGARG (0x01)
#define NTUCC_2_REGARG (0x02)
#define NTUCC_3_REGARG (0x03)
#define NTUCC_4_REGARG (0x04)
#define NTUCC_5_REGARG (0x05)
#define NTUCC_6_REGARG (0x06)
#define NTUCC_7_REGARG (0x07)
#define NTUCC_HAS_REGARG_MASK NTUCC_7_REGARG

#define NTUCC_REVERSE_OP (0x08)
#define NTUCC_AUTO_CLEAN (0x10)

#define NTUCC_WINDOWS_X64 (0x0100 | NTUCC_4_REGARG | NTUCC_AUTO_CLEAN)
#define NTU_CDECL
#define NTU_STDCALL
#define NTU_FASTCALL

#ifdef NTUCC_WINDOWS_X64
#define NTUCC_WINDOWS_X64_PASS_RCX (0x0101 | NTUCC_3_REGARG | NTUCC_AUTO_CLEAN)
#endif // NTUCC_WINDOWS_X64

#ifdef NTU_CDECL

#endif // NTU_CDECL

typedef int ntucc_t;

#define NTUCC_MAX_REGARG_COUNT 4

#define NTUCC_GET_REGARG_COUNT(ntu_cc) (ntu_cc & NTUCC_HAS_REGARG_MASK)
#define NTUCC_HAS_REGARG(ntu_cc) ((ntu_cc & NTUCC_HAS_REGARG_MASK) != 0)

#endif // !__NTU_CC__
