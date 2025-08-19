#ifndef CVE_ARM64_H
#define CVE_ARM64_H

#include "cubevec/math/vector.h"
#if defined(__aarch64__) && defined(CVE_FORCE_CPU_INSTRUCTIONS)


#include <arm_neon.h>

#define CVE_CPU_ARM64

/*********************************************
 *
 *               NEON HELPER FOR ARM64
 *
 *********************************************/

/*
 convertion
*/
#define CVE_Neon_FromVec2f(out, x) \
         out = *(float32x2_t*)&x;

#define CVE_Neon_ToVec2f(out, x) \
         out = *(CVE_Vec2f*)&x;

#define CVE_Neon_FromVec3f(out, x) \
         do { \
         	float32x4_t CVE_Neon_FromVec3f_mx; \
          (*(CVE_Vec3f*)&CVE_Neon_FromVec3f_mx) = x; \
          out = mx; \
         } while(0)

#define CVE_Neon_ToVec3f(out, x) \
         out = *(QX_Vec3f*)&x;

#define CVE_Neon_FromVec4f(out, x) \
         out = *(float32x4_t*)&x;

#define CVE_Neon_ToVec4f(out, x) \
         out = *(CVE_Vec4f*)&x;

/*
 uint neon helper
*/


#define CVE_Neon_FromVec2u(out, x) \
         out = *(uint32x2_t*)&x;

#define CVE_Neon_ToVec2u(out, x) \
         out = *(CVE_Vec2u*)&x;

#define CVE_Neon_FromVec3u(out, x) \
         do { \
         	uint32x4_t CVE_Neon_FromVec3u_mx; \
          (*(CVE_Vec3u*)&CVE_Neon_FromVec3u_mx) = x; \
          out = mx; \
         } while(0)

#define CVE_Neon_ToVec3u(out, x) \
         out = *(QX_Vec3u*)&x;

#define CVE_Neon_FromVec4u(out, x) \
         out = *(uint32x4_t*)&x;

#define CVE_Neon_ToVec4u(out, x) \
         out = *(CVE_Vec4u*)&x;


#endif //defined(__aarch64__)

#endif

