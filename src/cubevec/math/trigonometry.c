#include "cubevec/math/trigonometry.h"


/*
 approximated math functions
 these functions designed in way that it could easily 
 vectorize. and it also uses some polynomial tricks to 
 minimize the error and the calculation
*/


/* coefficients */
static const CVE_Float S0 =      (CVE_Float)( 0.008028e-00);
static const CVE_Float S1 =      (CVE_Float)(-0.166607e-00);
 
static const CVE_Float C0 =      (CVE_Float)(-0.001312e-00);
static const CVE_Float C1 =      (CVE_Float)( 0.041592e-00);
static const CVE_Float C2 =      (CVE_Float)(-0.499976e-00);
static const CVE_Float C3 =      (CVE_Float)( 0.999998e-00);


/* constants */
static const CVE_Float pi_half = (CVE_Float)(1.57079632);


/*
 cosine 
 approximated using "cos(sqrt(x))" 
 interval [0, pi/2]

 sine
 approximated using this formula : (sin(sqrt(x))-sqrt(x)) / (x * sqrt(x))
 interval [0, pi/2]
 sin(x) ≈ x * x3 * sin_poly(x2)

*/
void __cve_sincos(CVE_Float a, CVE_Float *s, CVE_Float *c) {
 CVE_Float mx, mx_s, mx_c, x2_c, x2_s, out_s, out_c;
 
 CVE_Uint sign_s, sign_c, flip_s, flip_c, q;
 
 sign_s      = a < (CVE_Float)0.0;
 
 CVE_Abs(a, a);
 
	a =         a - (CVE_Float)(CVE_Uint)(a * (CVE_Float)(0.1591549)) * (CVE_Float)(6.283185307);

 q =         ((CVE_Uint)(a * (CVE_Float)(0.6366197))+1);
 mx =        a;
 mx =        mx - (pi_half * (CVE_Float)(q-1));

 mx_s =      mx;
 flip_s =    (q == 2 || q == 4);
 sign_s =    sign_s ^ (q > 2);
 mx_s =      flip_s ? (pi_half - mx_s) : mx_s;
 x2_s =      mx_s * mx_s;
 out_s =     ((S0 *  x2_s + S1) * (x2_s * mx_s) + mx_s);
 out_s =     sign_s ? -out_s : out_s;
 *s = out_s;

 mx_c =      mx;
 flip_c =    (q == 2 || q == 4);
 sign_c =    (q == 2 || q == 3);
 mx_c =      flip_c ? (mx_c - pi_half) : mx_c;
 x2_c =      mx_c * mx_c;
 out_c =     (((C0 * x2_c + C1) * x2_c + C2) *  x2_c + C3);
 out_c =     sign_c ? -out_c : out_c;
 *c = out_c;
}


/*
 wrap the angle from [-tau, +tau]
*/
CVE_Float __cve_wrap_angle(CVE_Float a) {
 CVE_Uint negative;
 
 negative =  a < (CVE_Float)0.0;
 CVE_Abs(a, a);
	a =         a - (CVE_Float)(CVE_Uint)(a * (CVE_Float)(0.1591549)) * (CVE_Float)(6.283185307);
 return negative ? -a : a;
}




/*
 calculated using "sin(x)/cos(x)"
 this is much more efficient because it only perform single
 range reduction and remainder operation, unlike separate sin and cos
*/
CVE_Float __cve_tan(CVE_Float a) {
 CVE_Float mx, sx, cx, out, x2;
 CVE_Uint sign, flip, q;

 sign      = a < (CVE_Float)0.0;
 CVE_Abs(a, a);
	a =         a - (CVE_Float)(CVE_Uint)(a * (CVE_Float)(0.1591549)) * (CVE_Float)(6.283185307);


 mx =      a;
 q =       ((CVE_Uint)(mx * (CVE_Float)(0.6366197))+1);
 flip =    (q == 2 || q == 4);
 sign =    sign ^ flip;
 mx =      mx - (pi_half * (CVE_Float)(q-1));
 mx =      flip ? (pi_half - mx) : mx;
 x2 =      mx * mx;
 sx =      ((S0 * x2 + S1) *  (x2 * mx) + mx);
 cx =      (((C0 * x2 + C1) * x2 + C2) * x2 + C3);
 out =     sx / cx;
 out =     sign ? -out : out;
 return out;
}




