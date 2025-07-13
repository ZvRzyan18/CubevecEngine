/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_ROOTS_H
#define CVE_ROOTS_H

#include "cubevec/math/vector.h"
#include "cubevec/math/vector_operator.h"
#include "cubevec/math/common.h"
#include "cubevec/cpu/arm64.h"


/*********************************************
 *
 *               ROOTS
 *
 *********************************************/


/*
#if defined(QX_F32)
#define QX_MAGIC_NUMBER 0x5f3759df
#else
#define QX_MAGIC_NUMBER 0x5fe6eb50c7b537a9
#endif
*/


/*********************************************
 *
 *               INV SQRT
 *
 *********************************************/


/*
 roots
 
 since it uses bit hack, it only works in IEEE 754 float format
 otherwise, it use standard sqrt or instruction fsqrt
*/

//Fast Inv Sqrt (Quake III) algorithm
#if defined(CVE_CPU_ARM64)
#define CVE_InvSqrt(out, x) \
        do { \
         CVE_Float CVE_InvSqrt_x; \
         CVE_InvSqrt_x = x; \
         __asm__ volatile( \
         "fsqrt %s0, %s0 \n" \
         : "=w"(CVE_InvSqrt_x) \
         ); \
         out = 1.0f / CVE_InvSqrt_x; \
        } while(0)
#else
#define CVE_InvSqrt(out, x) \
        do { \
         CVE_Float CVE_InvSqrt_f, CVE_InvSqrt_mx, CVE_InvSqrt_x_half; \
         CVE_Uint CVE_InvSqrt_bits; \
         CVE_InvSqrt_bits =   0x5f3759df - ((*(CVE_Uint*)&x) >> 1); \
         CVE_InvSqrt_mx =     *(CVE_Float*)&CVE_InvSqrt_bits; \
         CVE_InvSqrt_x_half = x * 0.5; \
         CVE_InvSqrt_f =      CVE_InvSqrt_mx; \
         CVE_InvSqrt_f =      (CVE_InvSqrt_f * (1.5 - (CVE_InvSqrt_x_half * CVE_InvSqrt_f * CVE_InvSqrt_f))); \
         out = CVE_InvSqrt_f; \
        } while(0)
#endif

/*********************************************
 *
 *               SQRT
 *
 *********************************************/


#if defined(CVE_CPU_ARM64)
#define CVE_Sqrt(out, x) \
        do { \
         CVE_Float CVE_Sqrt_x; \
         CVE_Sqrt_x = x; \
         __asm__ volatile( \
         "fsqrt %s0, %s0 \n" \
         : "=w"(CVE_Sqrt_x) \
         ); \
         out = CVE_Sqrt_x; \
        } while(0)
#else
#define CVE_Sqrt(out, x) \
        do { \
         CVE_Float CVE_Sqrt_f; \
         CVE_InvSqrt(CVE_Sqrt_f, x); \
         out = x * CVE_Sqrt_f; \
        } while(0)
#endif


#endif

