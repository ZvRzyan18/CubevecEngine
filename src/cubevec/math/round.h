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

