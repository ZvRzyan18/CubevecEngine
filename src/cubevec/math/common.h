/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_COMMON_H
#define CVE_COMMON_H

#include "cubevec/math/vector_operator.h"
#include "cubevec/cpu/arm64.h"


/*********************************************
 *
 *               COMMON FUNCTIONS
 *
 *********************************************/

/*
 compare values 
 NOTE : please use this values for consistency
*/

#if defined(CVE_F32)

#define CVE_HUGE_FLOAT 1e+30
#define CVE_EPSILON_FLOAT 1e-3

#elif defined(CVE_F64)

#define CVE_HUGE_FLOAT 1e+300
#define CVE_EPSILON_FLOAT 1e-8

#endif



#define CVE_PI_FLOAT 3.1415926

/*
 these macros sould use SIMD instructions to
 optimize the calculations
*/

/*
 these should use abs instructions instead if available
*/


/*********************************************
 *
 *               ABS
 *
 *********************************************/


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Abs(out, a) \
        do { \
         __asm__ volatile( \
         "fabs %s0, %s1 \n" \
         : "=w"(out) \
         : "w"(a) \
         ); \
        } while(0)
#else
#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Abs(out, a) \
         out = fabsf(a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Abs(out, a) \
         out = fabs(a)
#else
#define CVE_Abs(out, a) \
        out = (a < 0.0) ? -a : a
#endif

#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Abs2f(out, a) \
        do { \
         float32x2_t CVE_Abs2f_x; \
         CVE_Neon_FromVec2f(CVE_Abs2f_x, a); \
         CVE_Abs2f_x = vabs_f32(CVE_Abs2f_x); \
         CVE_Neon_ToVec2f(out, CVE_Abs2f_x); \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Abs2f(out, a) \
        do { \
        out.x = fabsf(a.x); \
        out.y = fabsf(a.y); \
        } while(0)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Abs2f(out, a) \
        do { \
        out.x = fabs(a.x); \
        out.y = fabs(a.y); \
        } while(0)
#else
#define CVE_Abs2f(out, a) \
        do { \
        out.x = a.x < 0.0 ? -a.x : a.x; \
        out.y = a.y < 0.0 ? -a.y : a.y; \
        } while(0)
#endif

#endif 

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Abs3f(out, a) \
        do { \
         float32x4_t CVE_Abs3f_x; \
         CVE_Neon_FromVec3f(CVE_Abs3f_x, a); \
         CVE_Abs3f_x = vabsq_f32(CVE_Abs3f_x); \
         CVE_Neon_ToVec3f(out, CVE_Abs3f_x); \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Abs3f(out, a) \
        do { \
        out.x = fabsf(a.x); \
        out.y = fabsf(a.y); \
        out.z = fabsf(a.z); \
        } while(0)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Abs3f(out, a) \
        do { \
        out.x = fabs(a.x); \
        out.y = fabs(a.y); \
        out.z = fabs(a.z); \
        } while(0)
#else
#define CVE_Abs3f(out, a) \
        do { \
        out.x = a.x < 0.0 ? -a.x : a.x; \
        out.y = a.y < 0.0 ? -a.y : a.y; \
        out.z = a.z < 0.0 ? -a.z : a.z; \
        } while(0)
#endif

#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Abs4f(out, a) \
        do { \
         float32x4_t CVE_Abs4f_x; \
         CVE_Neon_FromVec4f(CVE_Abs4f_x, a); \
         CVE_Abs4f_x = vabsq_f32(CVE_Abs4f_x); \
         CVE_Neon_ToVec4f(out, CVE_Abs4f_x); \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Abs4f(out, x) \
        do { \
        out.x = fabsf(a.x); \
        out.y = fabsf(a.y); \
        out.z = fabsf(a.z); \
        out.z = fabsf(a.w); \
        } while(0)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Abs4f(out, x) \
        do { \
        out.x = fabs(a.x); \
        out.y = fabs(a.y); \
        out.z = fabs(a.z); \
        out.z = fabs(a.w); \
        } while(0)
#else
#define CVE_Abs4f(out, x) \
        do { \
        out.x = a.x < 0.0 ? -a.x : a.x; \
        out.y = a.y < 0.0 ? -a.y : a.y; \
        out.z = a.z < 0.0 ? -a.z : a.z; \
        out.z = a.w < 0.0 ? -a.w : a.w; \
        } while(0)
#endif

#endif


/*********************************************
 *
 *               MIN
 *
 *********************************************/


/*
 these macros should use SIMD instructions to optimize the
 calculations
*/

#define CVE_Min(out, a, b) \
        out = ((a < b) ? a : b)


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Min2f(out, a, b) \
        do { \
         float32x2_t CVE_Min2f_a, CVE_Min2f_b; \
         CVE_Neon_FromVec2f(CVE_Min2f_a, a); \
         CVE_Neon_FromVec2f(CVE_Min2f_b, b); \
         CVE_Min2f_a = vmin_f32(CVE_Min2f_a, CVE_Min2f_b); \
         CVE_Neon_ToVec2f(out, CVE_Min2f_a); \
        } while(0)
#else
#define CVE_Min2f(out, a, b) \
        do { \
         CVE_Min(out.x, a.x, b.x); \
         CVE_Min(out.y, a.y, b.y); \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Min3f(out, a, b) \
        do { \
         float32x4_t CVE_Min3f_a, CVE_Min3f_b; \
         CVE_Neon_FromVec3f(CVE_Min3f_a, a); \
         CVE_Neon_FromVec3f(CVE_Min3f_b, b); \
         CVE_Min3f_a = vminq_f32(CVE_Min3f_a, CVE_Min3f_b); \
         CVE_Neon_ToVec3f(out, CVE_Min3f_a); \
        } while(0)
#else
#define CVE_Min3f(out, a, b) \
        do { \
         CVE_Min(out.x, a.x, b.x); \
         CVE_Min(out.y, a.y, b.y); \
         CVE_Min(out.z, a.z, b.z); \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Min4f(out, a, b) \
        do { \
         float32x4_t CVE_Min4f_a, CVE_Min4f_b; \
         CVE_Neon_FromVec4f(CVE_Min4f_a, a); \
         CVE_Neon_FromVec4f(CVE_Min4f_b, b); \
         CVE_Min4f_a = vminq_f32(CVE_Min4f_a, CVE_Min4f_b); \
         CVE_Neon_ToVec4f(out, CVE_Min4f_a); \
        } while(0)
#else
#define CVE_Min4f(out, a, b) \
        do { \
         CVE_Min(out.x, a.x, b.x); \
         CVE_Min(out.y, a.y, b.y); \
         CVE_Min(out.z, a.z, b.z); \
         CVE_Min(out.w, a.w, b.w); \
        } while(0)
#endif


/*********************************************
 *
 *               MAX
 *
 *********************************************/



#define CVE_Max(out, a, b) \
        out = ((a > b) ? a : b)


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Max2f(out, a, b) \
        do { \
         float32x2_t CVE_Max2f_a, CVE_Max2f_b; \
         CVE_Neon_FromVec2f(CVE_Max2f_a, a); \
         CVE_Neon_FromVec2f(CVE_Max2f_b, b); \
         CVE_Max2f_a = vmax_f32(CVE_Max2f_a, CVE_Max2f_b); \
         CVE_Neon_ToVec2f(out, CVE_Max2f_a); \
        } while(0)
#else
#define CVE_Max2f(out, a, b) \
        do { \
         CVE_Max(out.x, a.x, b.x); \
         CVE_Max(out.y, a.y, b.y); \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Max3f(out, a, b) \
        do { \
         float32x4_t CVE_Max3f_a, CVE_Max3f_b; \
         CVE_Neon_FromVec3f(CVE_Max3f_a, a); \
         CVE_Neon_FromVec3f(CVE_Max3f_b, b); \
         CVE_Max3f_a = vmaxq_f32(CVE_Max3f_a, CVE_Max3f_b); \
         CVE_Neon_ToVec3f(out, CVE_Max3f_a); \
        } while(0)
#else
#define CVE_Max3f(out, a, b) \
        do { \
         CVE_Max(out.x, a.x, b.x); \
         CVE_Max(out.y, a.y, b.y); \
         CVE_Max(out.z, a.z, b.z); \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Max4f(out, a, b) \
        do { \
         float32x4_t CVE_Max4f_a, CVE_Max4f_b; \
         CVE_Neon_FromVec4f(CVE_Max4f_a, a); \
         CVE_Neon_FromVec4f(CVE_Max4f_b, b); \
         CVE_Max4f_a = vmaxq_f32(CVE_Max4f_a, CVE_Max4f_b); \
         CVE_Neon_ToVec4f(out, CVE_Max4f_a); \
        } while(0)
#else
#define CVE_Max4f(out, a, b) \
        do { \
         CVE_Max(out.x, a.x, b.x); \
         CVE_Max(out.y, a.y, b.y); \
         CVE_Max(out.z, a.z, b.z); \
         CVE_Max(out.w, a.w, b.w); \
        } while(0)
#endif


/*********************************************
 *
 *               APPROX EQUALS (FLOAT)
 *
 *********************************************/


#define CVE_ApproxEquals(out, a, b) \
        do { \
         CVE_Float CVE_ApproxEquals_diff; \
         CVE_ApproxEquals_diff = a-b; \
         CVE_Abs(CVE_ApproxEquals_diff, CVE_ApproxEquals_diff); \
         out = CVE_ApproxEquals_diff < CVE_EPSILON_FLOAT; \
        } while(0)

#define CVE_ApproxEquals2f(our, a, b) \
        do { \
         CVE_Vec2f CVE_ApproxEquals2f_diff, CVE_ApproxEquals2f_epsilon; \
         CVE_ScalarToVector2f(CVE_ApproxEquals2f_epsilon, CVE_EPSILON_FLOAT); \
         CVE_Sub2f(CVE_ApproxEquals2f_diff, a, b); \
         CVE_Abs2f(CVE_ApproxEquals2f_diff, CVE_ApproxEquals2f_diff); \
         CVE_LessThan2f(out, a, CVE_ApproxEquals2f_epsilon); \
        } while(0)



#define CVE_Cross2f(out, a, b) \
         out = (a.x * b.y - a.y * b.x)

#endif

