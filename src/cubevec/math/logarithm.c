#include "cubevec/math/logarithm.h"

/*
 logarithm approximation
*/

#if defined(CVE_F64)

static const CVE_Float LOG2_0 = -8.1615808498122383e-2;
static const CVE_Float LOG2_1 =  6.4514236358772082e-1;
static const CVE_Float LOG2_2 = -2.1206751311142674e-0;
static const CVE_Float LOG2_3 =  4.0700907918522014e-0;
static const CVE_Float LOG2_4 = -2.5128546239033371e-0;

#elif defined(CVE_F32)

static const CVE_Float LOG2_0 = -8.161580e-2f;
static const CVE_Float LOG2_1 =  6.451423e-1f;
static const CVE_Float LOG2_2 = -2.120675e-0f;
static const CVE_Float LOG2_3 =  4.070090e-0f;
static const CVE_Float LOG2_4 = -2.512854e-0f;

#endif


#define __log2(x) ((((LOG2_0 * x + LOG2_1) * x + LOG2_2) * x + LOG2_3) * x + LOG2_4)


#define __isignificand(x) 4607182418800017408U | ((*(CVE_Uint*)&x) & 0x000FFFFFFFFFFFFF)
#define __isignificandf(x) 1065353216U | ((*(CVE_Uint*)&x) & 0x007FFFFF)

#define __ilogb(x) (((*(CVE_Uint*)&x) >> 52)-1023)
#define __ilogbf(x) (((*(CVE_Uint*)&x) >> 23)-127)

/*
 this algorithm uses bit manipulation so it only works in ieee 754 
 float format. or else just use a std log2f/log2 instead.

 TODO : branchless optimization
*/
CVE_Float __cve_log2(CVE_Float a) {
#if defined(CVE_F64)

 CVE_Uint mantissa;
 CVE_Float mx;
 if((*(CVE_Uint*)&a >> 52) < 1023) { /* x < 1.0 */
  a = 1.0 / a;
  mantissa = __isignificand(a);
  mx = *(CVE_Float*)&mantissa;
  return -(__ilogb(a) + __log2(mx));
 }
 mantissa = __isignificand(a);
 mx = *(CVE_Float*)&mantissa;
 return __ilogb(a) + __log2(mx);

#elif defined(CVE_F32)

 CVE_Uint mantissa;
 CVE_Float mx;
 if((*(CVE_Uint*)&a >> 23) < 127) { /* x < 1.0 */
  a = 1.0f / a;
  mantissa = __isignificandf(a);
  mx = *(CVE_Float*)&mantissa;
  return -(__ilogbf(a) + __log2(mx));
 }
 mantissa = __isignificandf(a);
 mx = *(CVE_Float*)&mantissa;
 return __ilogbf(a) + __log2(mx);

#endif
}


