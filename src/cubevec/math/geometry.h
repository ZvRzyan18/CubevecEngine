/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef QX_GEOMTERY_H
#define QX_GEOMTERY_H

#include "cubevec/math/vector.h"
#include "cubevec/math/vector_operator.h"
#include "cubevec/math/roots.h"

/*
 these macros should take advantage the SIMD instructions
 to optimize the calculations 
*/

#define CVE_Dot2f(out, a, b) \
        do { \
         CVE_Float CVE_Dot2f_aa; \
         CVE_Dot2f_aa = (a.y * b.y); \
         CVE_Fma(out, a.x, b.x, CVE_Dot2f_aa); \
        } while(0)

#define CVE_Dot3f(out, a, b) \
        do { \
         CVE_Float CVE_Dot3f_aa; \
         CVE_Dot3f_aa = (a.z * b.z); \
         CVE_Fma(CVE_Dot3f_aa, a.y, b.y, CVE_Dot3f_aa); \
         CVE_Fma(out, a.x, b.x, CVE_Dot3f_aa); \
        } while(0)

#define CVE_Dot4f(a, b) \
        do { \
         CVE_Float CVE_Dot4f_aa; \
         CVE_Dot4f_aa = (a.w * b.w); \
         CVE_Fma(CVE_Dot4f_aa, a.z, b.z, CVE_Dot4f_aa); \
         CVE_Fma(CVE_Dot4f_aa, a.y, b.y, CVE_Dot4f_aa); \
         CVE_Fma(CVE_Dot4f_aa, a.x, b.x, CVE_Dot4f_aa); \
        } while(0)



#define CVE_Normalize2f(out, a) \
        do { \
         CVE_Float CVE_Normalize2f_inv_len; \
         CVE_Vec2f CVE_Normalize2f_inv_len_vec; \
         CVE_Dot2f(CVE_Normalize2f_inv_len, a, a); \
         CVE_InvSqrt(CVE_Normalize2f_inv_len, CVE_Normalize2f_inv_len); \
         CVE_ScalarToVector2f(CVE_Normalize2f_inv_len_vec, CVE_Normalize2f_inv_len); \
         CVE_Mul2f(out, a, CVE_Normalize2f_inv_len_vec); \
        } while(0)


#define CVE_Normalize3f(out, a) \
        do { \
         CVE_Float CVE_Normalize3f_inv_len; \
         CVE_Vec3f CVE_Normalize3f_inv_len_vec; \
         CVE_Dot3f(CVE_Normalize3f_inv_len, a, a); \
         CVE_InvSqrt(CVE_Normalize3f_inv_len, CVE_Normalize3f_inv_len); \
         CVE_ScalarToVector3f(CVE_Normalize3f_inv_len_vec, CVE_Normalize3f_inv_len); \
         CVE_Mul3f(out, a, CVE_Normalize3f_inv_len_vec); \
        } while(0)


#define CVE_Normalize4f(out, a) \
        do { \
         CVE_Float CVE_Normalize4f_inv_len; \
         CVE_Vec4f CVE_Normalize4f_inv_len_vec; \
         CVE_Dot4f(CVE_Normalize4f_inv_len, a, a); \
         CVE_InvSqrt(CVE_Normalize4f_inv_len, CVE_Normalize4f_inv_len); \
         CVE_ScalarToVector4f(CVE_Normalize4f_inv_len_vec, CVE_Normalize4f_inv_len); \
         CVE_Mul4f(out, a, CVE_Normalize4f_inv_len_vec); \
        } while(0)



#endif

