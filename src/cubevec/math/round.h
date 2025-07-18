/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_ROUND_H
#define CVE_ROUND_H

#include "cubevec/math/vector.h"
#include "cubevec/math/vector_operator.h"
#include "cubevec/math/common.h"
#include "cubevec/cpu/arm64.h"

/*********************************************
 *
 *               ROUND
 *
 *********************************************/

// TODO : still not ported into the new version of math
/*
 rounding floats
*/
#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Trunc(out, a) \
        do { \
         CVE_Float CVE_Trunc_mx; \
         CVE_Trunc_mx = a; \
          __asm__ volatile( \
          "frintz %s0, %s0 \n" \
          : "=w"(CVE_Trunc_mx) \
          ); \
          out = CVE_Trunc_mx; \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Trunc(out, a) \
         out = truncf(a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Trunc(out, a) \
         out = trunc(a)
#else
#define CVE_Trunc(out, a) \
         out = __cve_trunc(a)
#endif

#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Round(out, a) \
        do { \
         CVE_Float CVE_Trunc_mx; \
         CVE_Trunc_mx = a; \
          __asm__ volatile( \
          "frintn %s0, %s0 \n" \
          : "=w"(CVE_Trunc_mx) \
          ); \
          out = CVE_Trunc_mx; \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Round(out, a) \
         out = roundf(a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Round(out, a) \
         out = round(a)
#else
#define CVE_Round(out, a) \
         out = __cve_round(a)
#endif

#endif




#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Floor(out, a) \
        do { \
         CVE_Float CVE_Trunc_mx; \
         CVE_Trunc_mx = a; \
          __asm__ volatile( \
          "frintm %s0, %s0 \n" \
          : "=w"(CVE_Trunc_mx) \
          ); \
          out = CVE_Trunc_mx; \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Floor(out, a) \
         out = floorf(a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Floor(out, a) \
         out = floor(a)
#else
#define CVE_Floor(out, a) \
         out = __cve_floor(a)
#endif

#endif




#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Ceil(out, a) \
        do { \
         CVE_Float CVE_Trunc_mx; \
         CVE_Trunc_mx = a; \
          __asm__ volatile( \
          "frintp %s0, %s0 \n" \
          : "=w"(CVE_Trunc_mx) \
          ); \
          out = CVE_Trunc_mx; \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Ceil(out, a) \
         out = ceilf(a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Ceil(out, a) \
         out = ceil(a)
#else
#define CVE_Ceil(out, a) \
         out = __cve_ceil(a)
#endif

#endif


/*
 rounding modes
*/
#define CVE_TRUNC 0
#define CVE_ROUND 1
#define CVE_FLOOR 2
#define CVE_CEIL  3

#define CVE_LRint(out, a, mode) \
        do { \
         switch(mode) {\
          case CVE_TRUNC: \
           CVE_Trunc(out, a); \
          break; \
          case CVE_ROUND: \
           CVE_Round(out, a); \
          break; \
          case CVE_FLOOR: \
           CVE_Floor(out, a); \
          break; \
          case CVE_CEIL: \
           CVE_Ceil(out, a); \
          break; \
         } \
        } while(0)

CVE_Float __cve_trunc(CVE_Float a);
CVE_Float __cve_round(CVE_Float a);
CVE_Float __cve_floor(CVE_Float a);
CVE_Float __cve_ceil(CVE_Float a);


/*
 these functions only works on IEEE 754 float because it uses
 manual bit manipulation to calculate the rounding correctly

 but if some scalar/simd instructions available it should be used
 here instead
*/

/*
QX_FORCE_INLINE QX_Float QX_Trunc(QX_Float x) {
#if defined(QX_CPU_ARM64) && defined(QX_F32)
 __asm__ volatile(
  "frintz %s0, %s0 \n"
  : "=w"(x)
 );
 return x;
#else
	QX_Float out;
	QX_Uint x_bits, sign, negative_exponent, mantissa, integral, mask;
	QX_Uint exponent;
	x_bits =            *(QX_Uint*)&x;
	sign =              x_bits & QX_FLOAT_SIGN_BIT;
 x_bits =            x_bits & QX_FLOAT_SIGN_BIT_MASK;
 	
	exponent =          (x_bits >> QX_FLOAT_SIGNIFICAND);
 negative_exponent = exponent < QX_FLOAT_BIAS;
 exponent =          exponent - QX_FLOAT_BIAS;
 mantissa =          x_bits & QX_FLOAT_SIGNIFICAND_MASK;
 	
 integral =          exponent >= QX_FLOAT_SIGNIFICAND;
 mask =              QX_FLOAT_FULL_BITS << (QX_FLOAT_SIGNIFICAND - exponent);
 mantissa =          mantissa & mask;
 x_bits =            sign | ((exponent + QX_FLOAT_BIAS) << QX_FLOAT_SIGNIFICAND) | mantissa;
 out =               integral ? x : *(QX_Float*)&x_bits;
 out =               negative_exponent ? (QX_Float)0.0 : out;
 return out;
#endif
}
*/

/*
QX_FORCE_INLINE QX_Float QX_Ceil(QX_Float x) {
#if defined(QX_CPU_ARM64) && defined(QX_F32)
 __asm__ volatile(
  "frintp %s0, %s0 \n"
  : "=w"(x)
 );
 return x;
#else
	QX_Float whole, out, fract, one, zero;
	QX_Uint sign, greater;
	one =     (QX_Float)(1.0);
	zero =    (QX_Float)(0.0);
 sign =    (*(QX_Uint*)&x) & QX_FLOAT_SIGN_BIT;
 x =       QX_Abs(x);
	whole =   QX_Trunc(x);
	fract =   x - whole;
	greater = fract > zero;
 out =     (greater && !sign) ? whole+one : whole;
 sign =    sign | (*(QX_Uint*)&out);
 return *(QX_Float*)&sign;
#endif
}
*/

/*
QX_FORCE_INLINE QX_Float QX_Floor(QX_Float x) {
#if defined(QX_CPU_ARM64) && defined(QX_F32)
	 __asm__ volatile(
  "frintm %s0, %s0 \n"
  : "=w"(x)
 );
 return x;
#else
	QX_Float whole, out, fract, one, zero;
	QX_Uint sign, greater;
	one =     (QX_Float)(1.0);
	zero =    (QX_Float)(0.0);
 sign =    (*(QX_Uint*)&x) & QX_FLOAT_SIGN_BIT;
 x =       QX_Abs(x);
	whole =   QX_Trunc(x);
	fract =   x - whole;
	greater = fract > zero;
 out =     (greater && sign) ? whole+one : whole;
 sign =    sign | (*(QX_Uint*)&out);
 return *(QX_Float*)&sign;
#endif
}
*/

/*
QX_FORCE_INLINE QX_Float QX_Round(QX_Float x) {
#if defined(QX_CPU_ARM64) && defined(QX_F32)
 __asm__ volatile(
  "frintn %s0, %s0 \n"
  : "=w"(x)
 );
 return x;
#else
	QX_Float whole, out, fract, one, zero, half;
	QX_Uint sign, greater;
	one =     (QX_Float)(1.0);
	zero =    (QX_Float)(0.0);
	half =    (QX_Float)(0.5);
 sign =    (*(QX_Uint*)&x) & 0x80000000;
 x =       QX_Abs(x);
	whole =   QX_Trunc(x);
	fract =   x - whole;
	greater = fract > half;
 out =     (greater) ? whole+one : whole;
 sign =    sign | (*(QX_Uint*)&out);
 return *(QX_Float*)&sign;
#endif
}

*/

#endif

