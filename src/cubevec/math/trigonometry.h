/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_TRIGONOMETRY_H
#define CVE_TRIGONOMETRY_H

#include "cubevec/math/vector.h"
#include "cubevec/math/vector_operator.h"
#include "cubevec/math/common.h"
#include "cubevec/math/round.h"

/*********************************************
 *
 *               TRIGONOMETRY
 *
 *********************************************/

/*
 scalar
*/
/*
 there is a bug in sincos/sincosf function in math.h (arm64)
 so i used sin and cos instead.
*/
#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_SinCos(rad, a, b) \
        do { \
         a = sinf(rad); \
         b = cosf(rad); \
        } while(0)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_SinCos(rad, a, b) \
        do { \
         a = sin(rad); \
         b = cos(rad); \
        } while(0)
#else
#define CVE_SinCos(rad, a, b) \
        do { \
         __cve_sincos(rad, &a, &b); \
        } while(0)
#endif


#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_WrapAngle(out, a) \
         out = copysignf(fmodf(fabsf(a), 6.283185307f), a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_WrapAngle(out, a) \
         out = copysign(fmod(fabs(a), 6.283185307), a)
#else
#define CVE_WrapAngle(out, a) \
         out = __cve_wrap_angle(a)
#endif

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Tan(out, a) \
         out = tanf(a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Tan(out, a) \
         out = tan(a)
#else
#define CVE_Tan(out, a) \
         out = __cve_tan(a)
#endif

void __cve_sincos(CVE_Float a, CVE_Float *s, CVE_Float *c);
CVE_Float __cve_wrap_angle(CVE_Float a);
CVE_Float __cve_tan(CVE_Float a);


#endif

