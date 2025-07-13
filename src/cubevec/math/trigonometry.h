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

#include <math.h>
/*********************************************
 *
 *               TRIGONOMETRY
 *
 *********************************************/

//TODO : still not ported into the new version of math
/*
 approximated math functions
 these functions designed in way that it could easily 
 vectorize. and it also uses some polynomial tricks to 
 minimize the error and the calculation
*/


/*
 NOTE : these functions QX_Sin/QX_Cos/QX_Tan does not perform
 remainder and sign checking, meaning when the values x > tau or x < 0 will
 become inaccurate
*/


/*
 scalar
*/
#define CVE_SinCos(rad, a, b) \
        do { \
         a = sinf(rad); \
         b = cosf(rad); \
        } while(0)
/*
QX_FORCE_INLINE QX_Float QX_Sin(QX_Float x) {
 //this function is approximated using this formula : (sin(sqrt(x))-sqrt(x)) / (x * sqrt(x))
 //interval [0, pi/2]
 //sin(x) ≈ x * x3 * sin_poly(x2)
 //where : sin_poly(x) = (((C0 * x + C1) * x + C2) * x + C3)
 //for -x = -sin(abs(x))
 QX_Float mx, x2, out, pi_half, C0, C1;
 QX_Uint sign, flip, q;
 //coefficients 
 C0 =      (QX_Float)( 0.008028e-00);
 C1 =      (QX_Float)(-0.166607e-00);
 pi_half = (QX_Float)(1.57079632);
 mx =      x;
 // range reduction 
 q =       ((QX_Uint)(mx * (QX_Float)(0.6366197))+1);
 flip =    (q == 2 || q == 4);
 sign =    (q > 2);
 mx =      mx - (pi_half * (QX_Float)(q-1));
 mx =      flip ? (pi_half - mx) : mx;
 // polynomial 
 x2 =      mx * mx;
 out =     QX_Fma(QX_Fma(C0, x2, C1), (x2 * mx), mx);
 out =     sign ? -out : out;
 return out;
}


QX_FORCE_INLINE QX_Float QX_Cos(QX_Float x) {
 //approximated using "cos(sqrt(x))" 
 //interval [0, pi/2]
 QX_Float mx, x2, out, pi_half, C0, C1, C2, C3;
 QX_Uint sign, flip, q;
 // coefficients 
 C0 =      (QX_Float)(-0.001312e-00);
 C1 =      (QX_Float)( 0.041592e-00);
 C2 =      (QX_Float)(-0.499976e-00);
 C3 =      (QX_Float)( 0.999998e-00);
 pi_half = (QX_Float)(1.57079632);
 mx = x;
 // range reduction
 q =       ((QX_Uint)(mx * (QX_Float)(0.6366197))+1);
 flip =    (q == 2 || q == 4);
 sign =    (q == 2 || q == 3);
 mx =      mx - (pi_half * (QX_Float)(q-1));
 mx =      flip ? (mx - pi_half) : mx;
 // polynomial
 x2 =      mx * mx;
 out =     QX_Fma(QX_Fma(QX_Fma(C0, x2, C1), x2, C2), x2, C3);
 out =     sign ? -out : out;
 return out;
}


inline QX_Float QX_Tan(QX_Float x) {
 //calculated using "sin(x)/cos(x)"
 //this is much more efficient because it only perform single
 //range reduction and remainder operation, unlike separate sin and cos
 QX_Float mx, sx, cx, out, pi_half, x2, S0, S1, C0, C1, C2, C3;
 QX_Uint sign, flip, q;

 S0 =      (QX_Float)( 0.008028e-00);
 S1 =      (QX_Float)(-0.166607e-00);
 C0 =      (QX_Float)(-0.001312e-00);
 C1 =      (QX_Float)( 0.041592e-00);
 C2 =      (QX_Float)(-0.499976e-00);
 C3 =      (QX_Float)( 0.999998e-00);
 pi_half = (QX_Float)(1.57079632);
 
 mx =      x;
 // range reduction 
 q =       ((QX_Uint)(mx * (QX_Float)(0.6366197))+1);
 flip =    (q == 2 || q == 4);
 sign =    flip;
 mx =      mx - (pi_half * (QX_Float)(q-1));
 mx =      flip ? (pi_half - mx) : mx;
 // polynomial
 x2 =      mx * mx;
 sx =      QX_Fma(QX_Fma(S0, x2, S1), (x2 * mx), mx);
 cx =      QX_Fma(QX_Fma(QX_Fma(C0, x2, C1), x2, C2), x2, C3);
 out =     sx / cx;
 out =     sign ? -out : out;
 return out;
}
*/


/*
 this function is uses for rotation so it handles sign and full
 rotational angle unlike QX_Sin and QX_Cos
*/

/*
QX_FORCE_INLINE void QX_Sincos(QX_Float x, QX_Float* _s, QX_Float* _c) {
	QX_Uint sign;
	QX_Float sine;
	sign = x < 0.0;
	x =    QX_Abs(x);
 x =    x - QX_Trunc(x * (QX_Float)0.1591549) * (QX_Float)6.283185307;
	sine = QX_Sin(x);
	*_s = sign ? -sine : sine;
	*_c =  QX_Cos(x);
}

*/
/*
 vector trigonometry
*/

/*
 vector2
*/

/*

QX_FORCE_INLINE QX_Vec2f QX_Sin2f(QX_Vec2f x) {
 QX_Vec2f mx, x2, out, pi_half, C0, C1;
 QX_Vec2u sign, flip, q, one, two, four;
 C0 =      QX_ScalarToVector2f( 0.008028e-00);
 C1 =      QX_ScalarToVector2f(-0.166607e-00);
 pi_half = QX_ScalarToVector2f(1.57079632);
 one =     QX_ScalarToVector2u(1);
 two =     QX_ScalarToVector2u(2);
 four =    QX_ScalarToVector2u(4);
 mx =      x;
 mx =      QX_Abs2f(mx);
 q =       QX_Add2u(QX_ToUint2f(QX_Mul2f(mx, QX_ScalarToVector2f(0.6366197))), one);
 flip =    QX_BitwiseOr2u(QX_Equals2u(q, two), QX_Equals2u(q, four));
 sign =    QX_GreaterThan2u(q, two);
 mx =      QX_Sub2f(mx, QX_Mul2f(pi_half, QX_ToFloat2u(QX_Sub2u(q, one))));
 mx =      QX_Ternary2f(flip, QX_Sub2f(pi_half, mx), mx);
 x2 =      QX_Mul2f(mx, mx);
 out =     QX_Fma2f(QX_Fma2f(C0, x2, C1), QX_Mul2f(x2, mx), mx);
 out =     QX_Ternary2f(sign, QX_Negate2f(out), out);
 return out;
}


QX_FORCE_INLINE QX_Vec2f QX_Cos2f(QX_Vec2f x) {
 QX_Vec2f mx, x2, out, pi_half, C0, C1, C2, C3;
 QX_Vec2u sign, flip, q, one, two, three, four;
 C0 =      QX_ScalarToVector2f(-0.001312e-00);
 C1 =      QX_ScalarToVector2f( 0.041592e-00);
 C2 =      QX_ScalarToVector2f(-0.499976e-00);
 C3 =      QX_ScalarToVector2f( 0.999998e-00);
 pi_half = QX_ScalarToVector2f(1.57079632);
 one =     QX_ScalarToVector2u(1);
 two =     QX_ScalarToVector2u(2);
 three =   QX_ScalarToVector2u(3);
 four =    QX_ScalarToVector2u(4);
 mx =      x;
 q =       QX_Add2u(QX_ToUint2f(QX_Mul2f(mx, QX_ScalarToVector2f(0.6366197))), one);
 flip =    QX_BitwiseOr2u(QX_Equals2u(q, two), QX_Equals2u(q, four));
 sign =    QX_BitwiseOr2u(QX_Equals2u(q, two), QX_Equals2u(q, three));
 mx =      QX_Sub2f(mx, QX_Mul2f(pi_half, QX_ToFloat2u(QX_Sub2u(q, one))));
 mx =      QX_Ternary2f(flip, QX_Sub2f(mx, pi_half), mx);
 x2 =      QX_Mul2f(mx, mx);
 out =     QX_Fma2f(QX_Fma2f(QX_Fma2f(C0, x2, C1), x2, C2), x2, C3);
 out =     QX_Ternary2f(sign, QX_Negate2f(out), out);
 return out;
}


inline QX_Vec2f QX_Tan2f(QX_Vec2f x) {
 QX_Vec2f mx, sx, cx, out, pi_half, x2, S0, S1, C0, C1, C2, C3;
 QX_Vec2u sign, flip, q, one, two, four;
 S0 =      QX_ScalarToVector2f( 0.008028e-00);
 S1 =      QX_ScalarToVector2f(-0.166607e-00);
 C0 =      QX_ScalarToVector2f(-0.001312e-00);
 C1 =      QX_ScalarToVector2f( 0.041592e-00);
 C2 =      QX_ScalarToVector2f(-0.499976e-00);
 C3 =      QX_ScalarToVector2f( 0.999998e-00);
 pi_half = QX_ScalarToVector2f(1.57079632);
 one =     QX_ScalarToVector2u(1);
 two =     QX_ScalarToVector2u(2);
 four =    QX_ScalarToVector2u(4);
 mx =      x;
 q =       QX_Add2u(QX_ToUint2f(QX_Add2f(mx, QX_ScalarToVector2f(0.6366197))), one);
 flip =    QX_BitwiseOr2u(QX_Equals2u(q, two), QX_Equals2u(q, four));
 sign =    flip;
 mx =      QX_Sub2f(mx, QX_Mul2f(pi_half, QX_ToFloat2u(QX_Sub2u(q, one))));
 mx =      QX_Ternary2f(flip, QX_Sub2f(pi_half, mx), mx);
 x2 =      QX_Sub2f(mx, mx);
 sx =      QX_Fma2f(QX_Fma2f(S0, x2, S1), QX_Mul2f(x2, mx), mx);
 cx =      QX_Fma2f(QX_Fma2f(QX_Fma2f(C0, x2, C1), x2, C2), x2, C3);
 out =     QX_Div2f(sx, cx);
 out =     QX_Ternary2f(sign, QX_Negate2f(out), out);
 return out;
}
*/


#endif

