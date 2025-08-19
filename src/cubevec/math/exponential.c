#include "cubevec/math/exponential.h"

/*
 exponential approximation
*/
#if defined(CVE_F64)

static const CVE_Float EXP2_0 = 1.3697664475809267e-2;
static const CVE_Float EXP2_1 = 5.1690358205939469e-2;
static const CVE_Float EXP2_2 = 2.4163844572498163e-1;
static const CVE_Float EXP2_3 = 6.9296612266139567e-1;
static const CVE_Float EXP2_4 = 1.0000037044659370e-0;

#elif defined(CVE_F32)

static const CVE_Float EXP2_0 = 1.369766e-2f;
static const CVE_Float EXP2_1 = 5.169035e-2f;
static const CVE_Float EXP2_2 = 2.416384e-1f;
static const CVE_Float EXP2_3 = 6.929661e-1f;
static const CVE_Float EXP2_4 = 1.000003e-0f;

#endif

#define __exp2(x) ((((EXP2_0 * x + EXP2_1) * x + EXP2_2) * x + EXP2_3) * x + EXP2_4)

/*
 this algorithm uses bit manipulation so it only works in ieee 754 
 float format. or else just use a std exp2f/exp2 instead.
 
 TODO : branchless optimization
*/
CVE_Float __cve_exp2(CVE_Float a) {
#if defined(CVE_F64)

 if((*(CVE_Uint*)&a) & 0x8000000000000000) { /* x < 0.0f */
  *(CVE_Uint*)&a &= 0x7FFFFFFFFFFFFFFF;
  CVE_Uint out = ((CVE_Uint)(1023 + ((CVE_Uint)(a))) << 52);
  a -= (CVE_Uint)a;
  return 1.0 / ((*(CVE_Float*)(&out)) * __exp2(a));
 }
 CVE_Uint out = ((CVE_Uint)(1023 + ((CVE_Uint)(a))) << 52);
 a -= (CVE_Uint)a;
 return (*(CVE_Float*)(&out)) * __exp2(a);

#elif defined(CVE_F32)

 if((*(CVE_Uint*)&a) & 0x80000000) {/* x < 0.0f */
  *(CVE_Uint*)&a &= 0x7FFFFFFF;
  CVE_Uint out = ((CVE_Uint)(127 + ((CVE_Uint)(a))) << 23);
  a -= (CVE_Uint)a;
  return 1.0f / ((*(CVE_Float*)(&out)) * __exp2(a));
 }
 CVE_Uint out = ((CVE_Uint)(127 + ((CVE_Uint)(a))) << 23);
 a -= (CVE_Uint)a;
 return (*(CVE_Float*)(&out)) * __exp2(a);

#endif
}

