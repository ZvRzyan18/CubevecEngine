#ifndef CVE_EXPONENTIAL_H
#define CVE_EXPONENTIAL_H

#include "cubevec/math/vector.h"
#include "cubevec/math/vector_operator.h"
#include "cubevec/math/common.h"
#include "cubevec/math/round.h"


#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Exp2(out, a) \
         out = exp2f(a)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Exp2(out, a) \
         out = exp2(a)
#else
#define CVE_Exp2(out, a) \
         out = __cve_exp2(a)
#endif

CVE_Float __cve_exp2(CVE_Float a);

#endif

