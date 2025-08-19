/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_VECTOR_OPERATOR_H
#define CVE_VECTOR_OPERATOR_H

#include "cubevec/math/vector.h"
#include "cubevec/cpu/arm64.h"


/*********************************************
 *
 *               BASIC OPERATORS
 *
 *********************************************/

//TODO : still incomplete operators for some vector
/*
 these macros should be optimized by SIMD instructions
 instead
*/


/*
 convertion
*/
#define CVE_ToUint2f(out, x) \
        do { \
         out.x = (CVE_Uint)x.x; \
         out.y = (CVE_Uint)x.y; \
        } while(0)
       
#define CVE_ToFloat2u(out, x) \
        do { \
         out.x = (CVE_Float)x.x; \
         out.y = (CVE_Float)x.y; \
        } while(0)

#define CVE_ToUint3f(out, x) \
        do { \
         out.x = (CVE_Uint)x.x; \
         out.y = (CVE_Uint)x.y; \
         out.z = (CVE_Uint)x.z; \
        } while(0)
       
#define CVE_ToFloat3u(out, x) \
        do { \
         out.x = (CVE_Float)x.x; \
         out.y = (CVE_Float)x.y; \
         out.z = (CVE_Float)x.z; \
        } while(0)

#define CVE_ToUint4f(out, x) \
        do { \
         out.x = (CVE_Uint)x.x; \
         out.y = (CVE_Uint)x.y; \
         out.z = (CVE_Uint)x.z; \
         out.w = (CVE_Uint)x.w; \
        } while(0)
       
#define CVE_ToFloat4u(out, x) \
        do { \
         out.x = (CVE_Float)x.x; \
         out.y = (CVE_Float)x.y; \
         out.z = (CVE_Float)x.z; \
         out.w = (CVE_Float)x.w; \
        } while(0)

/*********************************************
 *
 *               VECTOR2 
 *
 *********************************************/


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_ScalarToVector2f(out, a) \
        do { \
         float32x2_t CVE_ScalarToVector2f_mx = vdup_n_f32(a); \
         CVE_Neon_ToVec2f(out, CVE_ScalarToVector2f_mx); \
        } while(0)
#else
#define CVE_ScalarToVector2f(out, a) \
        do { \
         out.x = a; \
         out.y = a; \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Negate2f(out, a) \
        do { \
         float32x2_t CVE_Negate2f_mx; \
         CVE_Neon_FromVec2f(CVE_Negate2f_mx, a); \
         CVE_Negate2f_mx = vneg_f32(CVE_Negate2f_mx); \
         CVE_Neon_ToVec2f(out, CVE_Negate2f_mx); \
        } while(0)
#else
#define CVE_Negate2f(out, a) \
        do { \
         out.x = -a.x; \
         out.y = -a.y; \
        } while(0)         
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Add2f(out, a, b) \
        do { \
         float32x2_t CVE_Add2f_ma, CVE_Add2f_mb; \
         CVE_Neon_FromVec2f(CVE_Add2f_ma, a); \
         CVE_Neon_FromVec2f(CVE_Add2f_mb, b); \
         CVE_Add2f_ma = vadd_f32(CVE_Add2f_ma, CVE_Add2f_mb); \
         CVE_Neon_ToVec2f(out, CVE_Add2f_ma); \
        } while(0)
#else
#define CVE_Add2f(out, a, b) \
        do { \
         out.x = a.x + b.x; \
         out.y = a.y + b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Sub2f(out, a, b) \
        do { \
         float32x2_t CVE_Sub2f_ma, CVE_Sub2f_mb; \
         CVE_Neon_FromVec2f(CVE_Sub2f_ma, a); \
         CVE_Neon_FromVec2f(CVE_Sub2f_mb, b); \
         CVE_Sub2f_ma = vsub_f32(CVE_Sub2f_ma, CVE_Sub2f_mb); \
         CVE_Neon_ToVec2f(out, CVE_Sub2f_ma); \
        } while(0)
#else
#define CVE_Sub2f(out, a, b) \
        do { \
         out.x = a.x - b.x; \
         out.y = a.y - b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Mul2f(out, a, b) \
        do { \
         float32x2_t CVE_Mul2f_ma, CVE_Mul2f_mb; \
         CVE_Neon_FromVec2f(CVE_Mul2f_ma, a); \
         CVE_Neon_FromVec2f(CVE_Mul2f_mb, b); \
         CVE_Mul2f_ma = vmul_f32(CVE_Mul2f_ma, CVE_Mul2f_mb); \
         CVE_Neon_ToVec2f(out, CVE_Mul2f_ma); \
        } while(0)
#else
#define CVE_Mul2f(out, a, b) \
        do { \
         out.x = a.x * b.x; \
         out.y = a.y * b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Div2f(out, a, b) \
        do { \
         float32x2_t CVE_Div2f_ma, CVE_Div2f_mb; \
         CVE_Neon_FromVec2f(CVE_Div2f_ma, a); \
         CVE_Neon_FromVec2f(CVE_Div2f_mb, b); \
         CVE_Div2f_ma = vdiv_f32(CVE_Div2f_ma, CVE_Div2f_mb); \
         CVE_Neon_ToVec2f(out, CVE_Div2f_ma); \
        } while(0)
#else
#define CVE_Div2f(out, a, b) \
        do { \
         out.x = a.x / b.x; \
         out.y = a.y / b.y; \
        } while(0)
#endif




#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_ScalarToVector2u(out, a) \
        do { \
         uint32x2_t CVE_ScalarToVector2u_mx = vdup_n_u32(a); \
         CVE_Neon_ToVec2u(out, CVE_ScalarToVector2u_mx); \
        } while(0)
#else
#define CVE_ScalarToVector2u(out, a) \
        do { \
         out.x = a; \
         out.y = a; \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Add2u(out, a, b) \
        do { \
         uint32x2_t CVE_Add2u_ma, CVE_Add2u_mb; \
         CVE_Neon_FromVec2u(CVE_Add2u_ma, a); \
         CVE_Neon_FromVec2u(CVE_Add2u_mb, b); \
         CVE_Add2u_ma = vadd_u32(CVE_Add2u_ma, CVE_Add2u_mb); \
         CVE_Neon_ToVec2u(out, CVE_Add2u_ma); \
        } while(0)
#else
#define CVE_Add2u(out, a, b) \
        do { \
         out.x = a.x + b.x; \
         out.y = a.y + b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Sub2u(out, a, b) \
        do { \
         uint32x2_t CVE_Sub2u_ma, CVE_Sub2u_mb; \
         CVE_Neon_FromVec2u(CVE_Sub2u_ma, a); \
         CVE_Neon_FromVec2u(CVE_Sub2u_mb, b); \
         CVE_Sub2u_ma = vsub_u32(CVE_Sub2u_ma, CVE_Sub2u_mb); \
         CVE_Neon_ToVec2u(out, CVE_Sub2u_ma); \
        } while(0)
#else
#define CVE_Sub2u(out, a, b) \
        do { \
         out.x = a.x - b.x; \
         out.y = a.y - b.y; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Mul2u(out, a, b) \
        do { \
         uint32x2_t CVE_Mul2u_ma, CVE_Mul2u_mb; \
         CVE_Neon_FromVec2u(CVE_Mul2u_ma, a); \
         CVE_Neon_FromVec2u(CVE_Mul2u_mb, b); \
         CVE_Mul2u_ma = vmul_u32(CVE_Mul2u_ma, CVE_Mul2u_mb); \
         CVE_Neon_ToVec2u(out, CVE_Mul2u_ma); \
        } while(0)
#else
#define CVE_Mul2u(out, a, b) \
        do { \
         out.x = a.x * b.x; \
         out.y = a.y * b.y; \
        } while(0)
#endif


#define CVE_Div2u(out, a, b) \
        do { \
         out.x = a.x / b.x; \
         out.y = a.y / b.y; \
        } while(0)

/*********************************************
 *
 *               VECTOR3
 *
 *********************************************/


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_ScalarToVector3f(out, a) \
        do { \
         float32x4_t CVE_ScalarToVector3f_mx = vdupq_n_f32(a); \
         CVE_Neon_ToVec3f(out, CVE_ScalarToVector3f_mx); \
        } while(0)
#else
#define CVE_ScalarToVector3f(out, a) \
        do { \
         out.x = a; \
         out.y = a; \
         out.z = a; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Negate3f(out, a) \
        do { \
         float32x4_t CVE_Negate3f_mx; \
         CVE_Neon_FromVec3f(CVE_Negate3f_mx, a); \
         CVE_Negate3f_mx = vnegq_f32(CVE_Negate3f_mx); \
         CVE_Neon_ToVec3f(out, CVE_Negate3f_mx); \
        } while(0)
#else
#define CVE_Negate3f(out, x) \
        do { \
         out.x = -a.x; \
         out.y = -a.y; \
         out.z = -a.z; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Add3f(out, a, b) \
        do { \
         float32x4_t CVE_Add3f_ma, CVE_Add3f_mb; \
         CVE_Neon_FromVec3f(CVE_Add3f_ma, a); \
         CVE_Neon_FromVec3f(CVE_Add3f_mb, b); \
         CVE_Add3f_ma = vaddq_f32(CVE_Add3f_ma, CVE_Add3f_mb); \
         CVE_Neon_ToVec3f(out, CVE_Add3f_ma); \
        } while(0)
#else
#define CVE_Add3f(out, a, b) \
        do { \
         out.x = a.x + b.x; \
         out.y = a.y + b.y; \
         out.z = a.z + b.z; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Sub3f(out, a, b) \
        do { \
         float32x4_t CVE_Sub3f_ma, CVE_Sub3f_mb; \
         CVE_Neon_FromVec3f(CVE_Sub3f_ma, a); \
         CVE_Neon_FromVec3f(CVE_Sub3f_mb, b); \
         CVE_Sub3f_ma = vsubq_f32(CVE_Sub3f_ma, CVE_Sub3f_mb); \
         CVE_Neon_ToVec3f(out, CVE_Sub3f_ma); \
        } while(0)
#else
#define CVE_Sub3f(out, a, b) \
        do { \
         out.x = a.x - b.x; \
         out.y = a.y - b.y; \
         out.z = a.z - b.z; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Mul3f(out, a, b) \
        do { \
         float32x4_t CVE_Mul3f_ma, CVE_Mul3f_mb; \
         CVE_Neon_FromVec3f(CVE_Mul3f_ma, a); \
         CVE_Neon_FromVec3f(CVE_Mul3f_mb, b); \
         CVE_Mul3f_ma = vmulq_f32(CVE_Mul3f_ma, CVE_Mul3f_mb); \
         CVE_Neon_ToVec3f(out, CVE_Mul3f_ma); \
        } while(0)
#else
#define CVE_Mul3f(out, a, b) \
        do { \
         out.x = a.x * b.x; \
         out.y = a.y * b.y; \
         out.z = a.z * b.z; \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Div3f(out, a, b) \
        do { \
         float32x4_t CVE_Div3f_ma, CVE_Div3f_mb; \
         CVE_Neon_FromVec3f(CVE_Div3f_ma, a); \
         CVE_Neon_FromVec3f(CVE_Div3f_mb, b); \
         CVE_Div3f_ma = vdivq_f32(CVE_Div3f_ma, CVE_Div3f_mb); \
         CVE_Neon_ToVec3f(out, CVE_Mul3f_ma); \
        } while(0)
#else
#define CVE_Div3f(out, a, b) \
        do { \
         out.x = a.x / b.x; \
         out.y = a.y / b.y; \
         out.z = a.z / b.z; \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_ScalarToVector3u(out, a) \
        do { \
         uint32x4_t CVE_ScalarToVector3u_mx = vdupq_n_u32(a); \
         CVE_Neon_ToVec3u(out, CVE_ScalarToVector3u_mx); \
        } while(0)
#else
#define CVE_ScalarToVector3u(out, a) \
        do { \
         out.x = a; \
         out.y = a; \
         out.z = a; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Add3u(out, a, b) \
        do { \
         uint32x4_t CVE_Add3u_ma, CVE_Add3u_mb; \
         CVE_Neon_FromVec3u(CVE_Add3u_ma, a); \
         CVE_Neon_FromVec3u(CVE_Add3u_mb, b); \
         CVE_Add3u_ma = vaddq_u32(CVE_Add3u_ma, CVE_Add3u_mb); \
         CVE_Neon_ToVec3u(out, CVE_Add3u_ma); \
        } while(0)
#else
#define CVE_Add3u(out, a, b) \
        do { \
         out.x = a.x + b.x; \
         out.y = a.y + b.y; \
         out.z = a.z + b.z; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Sub3u(out, a, b) \
        do { \
         uint32x4_t CVE_Sub3u_ma, CVE_Sub3u_mb; \
         CVE_Neon_FromVec3u(CVE_Sub3u_ma, a); \
         CVE_Neon_FromVec3u(CVE_Sub3u_mb, b); \
         CVE_Sub3u_ma = vsubq_u32(CVE_Sub3u_ma, CVE_Sub3u_mb); \
         CVE_Neon_ToVec3u(out, CVE_Sub3u_ma); \
        } while(0)
#else
#define CVE_Sub3u(out, a, b) \
        do { \
         out.x = a.x - b.x; \
         out.y = a.y - b.y; \
         out.z = a.z - b.z; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Mul3u(out, a, b) \
        do { \
         uint32x4_t CVE_Mul3u_ma, CVE_Mul3u_mb; \
         CVE_Neon_FromVec3u(CVE_Mul3u_ma, a); \
         CVE_Neon_FromVec3u(CVE_Mul3u_mb, b); \
         CVE_Mul3u_ma = vmulq_u32(CVE_Mul3u_ma, CVE_Mul3u_mb); \
         CVE_Neon_ToVec3u(out, CVE_Mul3u_ma); \
        } while(0)
#else
#define CVE_Mul3u(out, a, b) \
        do { \
         out.x = a.x * b.x; \
         out.y = a.y * b.y; \
         out.z = a.z * b.z; \
        } while(0)
#endif


#define CVE_Div3u(out, a, b) \
        do { \
         out.x = a.x / b.x; \
         out.y = a.y / b.y; \
         out.z = a.z / b.z; \
        } while(0)
  
/*********************************************
 *
 *               VECTOR4
 *
 *********************************************/


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_ScalarToVector4f(out, a) \
        do { \
         float32x4_t CVE_ScalarToVector4f_mx = vdupq_n_f32(a); \
         CVE_Neon_ToVec4f(out, CVE_ScalarToVector4f_mx); \
        } while(0)
#else
#define CVE_ScalarToVector4f(out, a) \
        do { \
         out.x = a; \
         out.y = a; \
         out.z = a; \
         out.w = a; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Negate4f(out, a) \
        do { \
         float32x4_t CVE_Negate4f_mx; \
         CVE_Neon_FromVec4f(CVE_Negate4f_mx, a); \
         CVE_Negate4f_mx = vnegq_f32(CVE_Negate4f_mx); \
         CVE_Neon_ToVec4f(out, CVE_Negate4f_mx); \
        } while(0)
#else
#define CVE_Negate4f(out, a) \
        do { \
         out.x = -a.x; \
         out.y = -a.y; \
         out.z = -a.z; \
         out.w = -a.w; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Add4f(out, a, b) \
        do { \
         float32x4_t CVE_Add4f_ma, CVE_Add4f_mb; \
         CVE_Neon_FromVec4f(CVE_Add4f_ma, a); \
         CVE_Neon_FromVec4f(CVE_Add4f_mb, b); \
         CVE_Add4f_ma = vaddq_f32(CVE_Add4f_ma, CVE_Add4f_mb); \
         CVE_Neon_ToVec4f(out, CVE_Add4f_ma); \
        } while(0)
#else
#define CVE_Add4f(out, a, b) \
        do { \
         out.x = a.x + b.x; \
         out.y = a.y + b.y; \
         out.z = a.z + b.z; \
         out.w = a.w + b.w; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Sub4f(out, a, b) \
        do { \
         float32x4_t CVE_Sub4f_ma, CVE_Sub4f_mb; \
         CVE_Neon_FromVec4f(CVE_Sub4f_ma, a); \
         CVE_Neon_FromVec4f(CVE_Sub4f_mb, b); \
         CVE_Sub4f_ma = vsubq_f32(CVE_Sub4f_ma, CVE_Sub4f_mb); \
         CVE_Neon_ToVec4f(out, CVE_Sub4f_ma); \
        } while(0)
#else
#define CVE_Sub4f(out, a, b) \
        do { \
         out.x = a.x - b.x; \
         out.y = a.y - b.y; \
         out.z = a.z - b.z; \
         out.w = a.w - b.w; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Mul4f(out, a, b) \
        do { \
         float32x4_t CVE_Mul4f_ma, CVE_Mul4f_mb; \
         CVE_Neon_FromVec4f(CVE_Mul4f_ma, a); \
         CVE_Neon_FromVec4f(CVE_Mul4f_mb, b); \
         CVE_Mul4f_ma = vmulq_f32(CVE_Mul4f_ma, CVE_Mul4f_mb); \
         CVE_Neon_ToVec4f(out, CVE_Mul4f_ma); \
        } while(0)
#else
#define CVE_Mul4f(out, a, b) \
        do { \
         out.x = a.x * b.x; \
         out.y = a.y * b.y; \
         out.z = a.z * b.z; \
         out.w = a.w * b.w; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Div4f(out, a, b) \
        do { \
         float32x4_t CVE_Div4f_ma, CVE_Div4f_mb; \
         CVE_Neon_FromVec4f(CVE_Div4f_ma, a); \
         CVE_Neon_FromVec4f(CVE_Div4f_mb, b); \
         CVE_Div4f_ma = vdivq_f32(CVE_Div4f_ma, CVE_Div4f_mb); \
         CVE_Neon_ToVec4f(out, CVE_Div4f_ma); \
        } while(0)
#else
#define CVE_Div4f(out, a, b) \
        do { \
         out.x = a.x / b.x; \
         out.y = a.y / b.y; \
         out.z = a.z / b.z; \
         out.w = a.w / b.w; \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_ScalarToVector4u(out, a) \
        do { \
         uint32x4_t CVE_ScalarToVector4u_mx = vdupq_n_u32(a); \
         CVE_Neon_ToVec4u(out, CVE_ScalarToVector4u_mx); \
        } while(0)
#else
#define CVE_ScalarToVector4u(out, a) \
        do { \
         out.x = a; \
         out.y = a; \
         out.z = a; \
         out.w = a; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Add4u(out, a, b) \
        do { \
         uint32x4_t CVE_Add4u_ma, CVE_Add4u_mb; \
         CVE_Neon_FromVec4u(CVE_Add4u_ma, a); \
         CVE_Neon_FromVec4u(CVE_Add4u_mb, b); \
         CVE_Add4u_ma = vaddq_u32(CVE_Add4u_ma, CVE_Add4u_mb); \
         CVE_Neon_ToVec4u(out, CVE_Add4u_ma); \
        } while(0)
#else
#define CVE_Add4u(out, a, b) \
        do { \
         out.x = a.x + b.x; \
         out.y = a.y + b.y; \
         out.z = a.z + b.z; \
         out.w = a.w + b.w; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Sub4u(out, a, b) \
        do { \
         uint32x4_t CVE_Sub4u_ma, CVE_Sub4u_mb; \
         CVE_Neon_FromVec4u(CVE_Sub4u_ma, a); \
         CVE_Neon_FromVec4u(CVE_Sub4u_mb, b); \
         CVE_Sub4u_ma = vsubq_u32(CVE_Sub4u_ma, CVE_Sub4u_mb); \
         CVE_Neon_ToVec4u(out, CVE_Sub4u_ma); \
        } while(0)
#else
#define CVE_Sub4u(out, a, b) \
        do { \
         out.x = a.x - b.x; \
         out.y = a.y - b.y; \
         out.z = a.z - b.z; \
         out.w = a.w - b.w; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Mul4u(out, a, b) \
        do { \
         uint32x4_t CVE_Mul4u_ma, CVE_Mul4u_mb; \
         CVE_Neon_FromVec4u(CVE_Mul4u_ma, a); \
         CVE_Neon_FromVec4u(CVE_Mul4u_mb, b); \
         CVE_Mul4u_ma = vmulq_u32(CVE_Mul4u_ma, CVE_Mul4u_mb); \
         CVE_Neon_ToVec4u(out, CVE_Mul4u_ma); \
        } while(0)
#else
#define CVE_Mul4u(out, a, b) \
        do { \
         out.x = a.x * b.x; \
         out.y = a.y * b.y; \
         out.z = a.z * b.z; \
         out.w = a.w * b.w; \
        } while(0)
#endif


#define CVE_Div4u(out, a, b) \
        do { \
         out.x = a.x / b.x; \
         out.y = a.y / b.y; \
         out.z = a.z / b.z; \
         out.w = a.w / b.w; \
        } while(0)

/*********************************************
 *
 *               FUSED MUL, ADD (FMA)
 *
 *********************************************/


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Fma(out, a, b, c) \
        do { \
          __asm__ volatile( \
          "fmadd %s0, %s1, %s2, %s3 \n" \
          : "=w"(out) \
          : "w"(a), "w"(b), "w"(c) \
         );  \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Fma(out, a, b, c) \
         out = fmaf(a, b, c)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Fma(out, a, b, c) \
         out = fma(a, b, c)
#else
#define CVE_Fma(out, a, b, c) \
        out = a * b + c;
#endif

#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Fma2f(out, a, b, c) \
        do { \
        	float32x2_t CVE_Fma2f_a, CVE_Fma2f_b, CVE_Fma2f_c; \
        	CVE_Neon_FromVec2f(CVE_Fma2f_a, a); \
        	CVE_Neon_FromVec2f(CVE_Fma2f_b, b); \
        	CVE_Neon_FromVec2f(CVE_Fma2f_c, c); \
        	CVE_Fma2f_a = vfma_f32(CVE_Fma2f_c, CVE_Fma2f_a, CVE_Fma2f_b); \
        	CVE_Neon_ToVec2f(out, CVE_Fma2f_a); \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Fma2f(out, a, b, c) \
         do { \
          out.x = fmaf(a.x, b.x, c.x); \
          out.y = fmaf(a.y, b.y, c.y); \
         } while(0)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Fma2f(out, a, b, c) \
         do { \
          out.x = fma(a.x, b.x, c.x); \
          out.y = fma(a.y, b.y, c.y); \
         } while(0)
#else
#define CVE_Fma2f(out, a, b, c) \
         do { \
          out.x = a.x * b.x + c.x; \
          out.y = a.y * b.y + c.y; \
         } while(0)
#endif

#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Fma3f(out, a, b, c) \
        do { \
        	float32x4_t CVE_Fma3f_a, CVE_Fma3f_b, CVE_Fma3f_c; \
        	CVE_Neon_FromVec3f(CVE_Fma3f_a, a); \
        	CVE_Neon_FromVec3f(CVE_Fma3f_b, b); \
        	CVE_Neon_FromVec3f(CVE_Fma3f_c, c); \
        	CVE_Fma3f_a = vfmaq_f32(CVE_Fma3f_c, CVE_Fma3f_a, CVE_Fma3f_b); \
        	CVE_Neon_ToVec3f(out, CVE_Fma3f_a); \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Fma3f(out, a, b, c) \
         do { \
          out.x = fmaf(a.x, b.x, c.x); \
          out.y = fmaf(a.y, b.y, c.y); \
          out.z = fmaf(a.z, b.z, c.z); \
         } while(0)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Fma3f(out, a, b, c) \
         do { \
          out.x = fma(a.x, b.x, c.x); \
          out.y = fma(a.y, b.y, c.y); \
          out.z = fma(a.z, b.z, c.z); \
         } while(0)
#else
#define CVE_Fma3f(out, a, b, c) \
         do { \
          out.x = a.x * b.x + c.x; \
          out.y = a.y * b.y + c.y; \
          out.z = a.z * b.z + c.z; \
         } while(0)
#endif

#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Fma4f(out, a, b, c) \
        do { \
        	float32x4_t CVE_Fma4f_a, CVE_Fma4f_b, CVE_Fma4f_c; \
        	CVE_Neon_FromVec4f(CVE_Fma4f_a, a); \
        	CVE_Neon_FromVec4f(CVE_Fma4f_b, b); \
        	CVE_Neon_FromVec4f(CVE_Fma4f_c, c); \
        	CVE_Fma4f_a = vfmaq_f32(CVE_Fma4f_c, CVE_Fma4f_a, CVE_Fma4f_b); \
        	CVE_Neon_ToVec4f(out, CVE_Fma4f_a); \
        } while(0)
#else

#if defined(CVE_USE_STD_MATH) && defined(CVE_F32)
#define CVE_Fma4f(out, a, b, c) \
         do { \
          out.x = fmaf(a.x, b.x, c.x); \
          out.y = fmaf(a.y, b.y, c.y); \
          out.z = fmaf(a.z, b.z, c.z); \
          out.w = fmaf(a.w, b.w, c.w); \
         } while(0)
#elif defined(CVE_USE_STD_MATH) && defined(CVE_F64)
#define CVE_Fma4f(out, a, b, c) \
         do { \
          out.x = fma(a.x, b.x, c.x); \
          out.y = fma(a.y, b.y, c.y); \
          out.z = fma(a.z, b.z, c.z); \
          out.w = fma(a.w, b.w, c.w); \
         } while(0)
#else
#define CVE_Fma4f(out, a, b, c) \
         do { \
          out.x = a.x * b.x + c.x; \
          out.y = a.y * b.y + c.y; \
          out.z = a.z * b.z + c.z; \
          out.w = a.w * b.w + c.w; \
         } while(0)
#endif

#endif

/*********************************************
 *
 *               SELECT (TERNARY)
 *
 *********************************************/


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Ternary2f(out, cond, a, b) \
        do { \
         uint32x2_t CVE_Ternary2f_c; \
         float32x2_t CVE_Ternary2f_a, CVE_Ternary2f_b; \
         CVE_Neon_FromVec2u(CVE_Ternary2f_c, cond); \
         CVE_Neon_FromVec2f(CVE_Ternary2f_a, a); \
         CVE_Neon_FromVec2f(CVE_Ternary2f_b, b); \
         CVE_Ternary2f_a = vbsl_f32(CVE_Ternary2f_c, CVE_Ternary2f_a, CVE_Ternary2f_b); \
         CVE_Neon_ToVec2f(out, CVE_Ternary2f_a); \
        } while(0)
#else
#define CVE_Ternary2f(out, cond, a, b) \
        do { \
        	out.x = cond.x ? a.x : b.x; \
        	out.y = cond.y ? a.y : b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Ternary3f(out, cond, a, b) \
        do { \
         uint32x4_t CVE_Ternary3f_c; \
         float32x4_t CVE_Ternary3f_a, CVE_Ternary3f_b; \
         CVE_Neon_FromVec3u(CVE_Ternary3f_c, cond); \
         CVE_Neon_FromVec3f(CVE_Ternary3f_a, a); \
         CVE_Neon_FromVec3f(CVE_Ternary3f_b, b); \
         CVE_Ternary3f_a = vbslq_f32(CVE_Ternary3f_c, CVE_Ternary3f_a, CVE_Ternary3f_b); \
         CVE_Neon_ToVec3f(out, CVE_Ternary3f_a); \
        } while(0)
#else
#define CVE_Ternary3f(out, cond, a, b) \
        do { \
        	out.x = cond.x ? a.x : b.x; \
        	out.y = cond.y ? a.y : b.y; \
        	out.z = cond.z ? a.z : b.z; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Ternary4f(out, cond, a, b) \
        do { \
         uint32x4_t CVE_Ternary4f_c; \
         float32x4_t CVE_Ternary4f_a, CVE_Ternary4f_b; \
         CVE_Neon_FromVec4u(CVE_Ternary4f_c, cond); \
         CVE_Neon_FromVec4f(CVE_Ternary4f_a, a); \
         CVE_Neon_FromVec4f(CVE_Ternary4f_b, b); \
         CVE_Ternary4f_a = vbslq_f32(CVE_Ternary4f_c, CVE_Ternary4f_a, CVE_Ternary4f_b); \
         CVE_Neon_ToVec4f(out, CVE_Ternary4f_a); \
        } while(0)
#else
#define CVE_Ternary4f(out, cond, a, b) \
        do { \
        	out.x = cond.x ? a.x : b.x; \
        	out.y = cond.y ? a.y : b.y; \
        	out.z = cond.z ? a.z : b.z; \
        	out.w = cond.w ? a.w : b.w; \
        } while(0)
#endif

/*********************************************
 *
 *               BOOLEAN OPERATOR
 *
 *********************************************/



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_Equals2u(out, a, b) \
        do { \
        	uint32x2_t CVE_Equals2u_a, CVE_Equals2u_b; \
         CVE_Neon_FromVec2u(CVE_Equals2u_a, a); \
         CVE_Neon_FromVec2u(CVE_Equals2u_b, b); \
         CVE_Equals2u_a = vceq_u32(CVE_Equals2u_a, CVE_Equals2u_b); \
         CVE_Neon_ToVec2u(out, CVE_Equals2u_a); \
        } while(0)
#else
#define CVE_Equals2u(out, a, b) \
        do { \
         out.x = a.x == b.x; \
         out.y = a.y == b.y; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_NotEquals2u(out, a, b) \
        do { \
        	uint32x2_t CVE_NotEquals2u_a, CVE_NotEquals2u_b; \
         CVE_Neon_FromVec2u(CVE_NotEquals2u_a, a); \
         CVE_Neon_FromVec2u(CVE_NotEquals2u_b, b); \
         CVE_NotEquals2u_a = vmvn_u32(vceq_u32(CVE_NotEquals2u_a, CVE_NotEquals2u_b)); \
         CVE_Neon_ToVec2u(out, CVE_NotEquals2u_a); \
        } while(0)
#else
#define CVE_NotEquals2u(out, a, b) \
        do { \
         out.x = a.x != b.x; \
         out.y = a.y != b.y; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_GreaterThan2u(out, a, b) \
        do { \
        	uint32x2_t CVE_GreaterThan2u_a, CVE_GreaterThan2u_b; \
         CVE_Neon_FromVec2u(CVE_GreaterThan2u_a, a); \
         CVE_Neon_FromVec2u(CVE_GreaterThan2u_b, b); \
         CVE_GreaterThan2u_a = vcgt_u32(CVE_GreaterThan2u_a, CVE_GreaterThan2u_b); \
         CVE_Neon_ToVec2u(out, CVE_GreaterThan2u_a); \
        } while(0)
#else
#define CVE_GreaterThan2u(out, a, b) \
        do { \
         out.x = a.x > b.x; \
         out.y = a.y > b.y; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_GreaterThan2f(out, a, b) \
        do { \
        	float32x2_t CVE_GreaterThan2f_a, CVE_GreaterThan2f_b; \
        	uint32x2_t CVE_GreaterThan2f_c; \
         CVE_Neon_FromVec2f(CVE_GreaterThan2f_a, a); \
         CVE_Neon_FromVec2f(CVE_GreaterThan2f_b, b); \
         CVE_GreaterThan2f_c = vcgt_f32(CVE_GreaterThan2f_a, CVE_GreaterThan2f_b); \
         CVE_Neon_ToVec2u(out, CVE_GreaterThan2f_c); \
        } while(0)
#else
#define CVE_GreaterThan2f(out, a, b) \
        do { \
         out.x = a.x > b.x; \
         out.y = a.y > b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_GreaterThanEquals2u(out, a, b) \
        do { \
        	uint32x2_t CVE_GreaterThanEquals2u_a, CVE_GreaterThanEquals2u_b; \
         CVE_Neon_FromVec2u(CVE_GreaterThanEquals2u_a, a); \
         CVE_Neon_FromVec2u(CVE_GreaterThanEquals2u_b, b); \
         CVE_GreaterThanEquals2u_a = vcge_u32(CVE_GreaterThanEquals2u_a, CVE_GreaterThanEquals2u_b); \
         CVE_Neon_ToVec2u(out, CVE_GreaterThanEquals2u_a); \
        } while(0)
#else
#define CVE_GreaterThanEquals2u(out, a, b) \
        do { \
         out.x = a.x >= b.x; \
         out.y = a.y >= b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_GreaterThanEquals2f(out, a, b) \
        do { \
        	float32x2_t CVE_GreaterThanEquals2f_a, CVE_GreaterThanEquals2f_b; \
        	uint32x2_t CVE_GreaterThanEquals2f_c; \
         CVE_Neon_FromVec2f(CVE_GreaterThanEquals2f_a, a); \
         CVE_Neon_FromVec2f(CVE_GreaterThanEquals2f_b, b); \
         CVE_GreaterThanEquals2f_c = vcgt_f32(CVE_GreaterThanEquals2f_a, CVE_GreaterThanEquals2f_b); \
         CVE_Neon_ToVec2u(out, CVE_GreaterThanEquals2f_c); \
        } while(0)
#else
#define CVE_GreaterThanEquals2f(out, a, b) \
        do { \
         out.x = a.x >= b.x; \
         out.y = a.y >= b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_LessThan2u(out, a, b) \
        do { \
        	uint32x2_t CVE_LessThan2u_a, CVE_LessThan2u_b; \
         CVE_Neon_FromVec2u(CVE_LessThan2u_a, a); \
         CVE_Neon_FromVec2u(CVE_LessThan2u_b, b); \
         CVE_LessThan2u_a = vclt_u32(CVE_LessThan2u_a, CVE_LessThan2u_b); \
         CVE_Neon_ToVec2u(out, CVE_LessThan2u_a); \
        } while(0)
#else
#define CVE_LessThan2u(out, a, b) \
        do { \
         out.x = a.x < b.x; \
         out.y = a.y < b.y; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_LessThan2f(out, a, b) \
        do { \
        	float32x2_t CVE_LessThan2f_a, CVE_LessThan2f_b; \
        	uint32x2_t CVE_LessThan2f_c; \
         CVE_Neon_FromVec2f(CVE_LessThan2f_a, a); \
         CVE_Neon_FromVec2f(CVE_LessThan2f_b, b); \
         CVE_LessThan2f_c = vclt_f32(CVE_LessThan2f_a, CVE_LessThan2f_b); \
         CVE_Neon_ToVec2u(out, CVE_LessThan2f_c); \
        } while(0)
#else
#define CVE_LessThan2f(out, a, b) \
        do { \
         out.x = a.x < b.x; \
         out.y = a.y < b.y; \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_LessThanEquals2u(out, a, b) \
        do { \
        	uint32x2_t CVE_LessThanEquals_a, CVE_LessThanEquals_b; \
         CVE_Neon_FromVec2u(CVE_LessThanEquals_a, a); \
         CVE_Neon_FromVec2u(CVE_LessThanEquals_b, b); \
         CVE_LessThanEquals_a = vcle_u32(CVE_LessThanEquals_a, CVE_LessThanEquals_b); \
         CVE_Neon_ToVec2u(out, CVE_LessThanEquals_a); \
        } while(0)
#else
#define CVE_LessThanEquals2u(out, a, b) \
        do { \
         out.x = a.x <= b.x; \
         out.y = a.y <= b.y; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_LessThanEquals2f(out, a, b) \
        do { \
        	float32x2_t CVE_LessThanEquals2f_a, CVE_LessThanEquals2f_b; \
        	uint32x2_t CVE_LessThanEquals2f_c; \
         CVE_Neon_FromVec2f(CVE_LessThanEquals2f_a, a); \
         CVE_Neon_FromVec2f(CVE_LessThanEquals2f_b, b); \
         CVE_LessThanEquals2f_c = vcle_f32(CVE_LessThanEquals2f_a, CVE_LessThanEquals2f_b); \
         CVE_Neon_ToVec2u(out, CVE_LessThanEquals2f_c); \
        } while(0)
#else
#define CVE_LessThanEquals2f(out, a, b) \
        do { \
         out.x = a.x <= b.x; \
         out.y = a.y <= b.y; \
        } while(0)
#endif



/*********************************************
 *
 *               BIT OPERATORS
 *
 *********************************************/


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_BitwiseAnd2u(out, a, b) \
        do { \
        	uint32x2_t CVE_BitwiseAnd2u_a, CVE_BitwiseAnd2u_b; \
         CVE_Neon_FromVec2u(CVE_BitwiseAnd2u_a, a); \
         CVE_Neon_FromVec2u(CVE_BitwiseAnd2u_b, b); \
         CVE_BitwiseAnd2u_a = vand_u32(CVE_BitwiseAnd2u_a, CVE_BitwiseAnd2u_b); \
         CVE_Neon_ToVec2u(out, CVE_BitwiseAnd2u_a); \
        } while(0)
#else
#define CVE_BitwiseAnd2u(out, a, b) \
        do { \
         out.x = a.x & b.x; \
         out.y = a.y & b.y; \
        } while(0)
#endif



#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_BitwiseOr2u(out, a, b) \
        do { \
        	uint32x2_t CVE_BitwiseOr2u_a, CVE_BitwiseOr2u_b; \
         CVE_Neon_FromVec2u(CVE_BitwiseOr2u_a, a); \
         CVE_Neon_FromVec2u(CVE_BitwiseOr2u_b, b); \
         CVE_BitwiseOr2u_a = vorr_u32(CVE_BitwiseOr2u_a, CVE_BitwiseOr2u_b); \
         CVE_Neon_ToVec2u(out, CVE_BitwiseOr2u_a); \
        } while(0)
#else
#define CVE_BitwiseOr2u(out, a, b) \
        do { \
         out.x = a.x | b.x; \
         out.y = a.y | b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_BitwiseXor2u(out, a, b) \
        do { \
        	uint32x2_t CVE_BitwiseXor2u_a, CVE_BitwiseXor2u_b; \
         CVE_Neon_FromVec2u(CVE_BitwiseXor2u_a, a); \
         CVE_Neon_FromVec2u(CVE_BitwiseXor2u_b, b); \
         CVE_BitwiseXor2u_a = veor_u32(CVE_BitwiseXor2u_a, CVE_BitwiseXor2u_b); \
         CVE_Neon_ToVec2u(out, CVE_BitwiseXor2u_a); \
        } while(0)
#else
#define CVE_BitwiseXor2u(out, a, b) \
        do { \
         out.x = a.x ^ b.x; \
         out.y = a.y ^ b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_BitshiftRight2u(out, a, b) \
        do { \
        	uint32x2_t CVE_BitshiftRight2u_a, CVE_BitshiftRight2u_b; \
         CVE_Neon_FromVec2u(CVE_BitshiftRight2u_a, a); \
         CVE_Neon_FromVec2u(CVE_BitshiftRight2u_b, b); \
         CVE_BitshiftRight2u_a = vshl_u32(CVE_BitshiftRight2u_a, vneg_s32(CVE_BitshiftRight2u_b)); \
         CVE_Neon_ToVec2u(out, CVE_BitshiftRight2u_a); \
        } while(0)
#else
#define CVE_BitshiftRight2u(out, a, b) \
        do { \
         out.x = a.x >> b.x; \
         out.y = a.y >> b.y; \
        } while(0)
#endif


#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_BitshiftLeft2u(out, a, b) \
        do { \
        	uint32x2_t CVE_BitshiftLeft2u_a, CVE_BitshiftLeft2u_b; \
         CVE_Neon_FromVec2u(CVE_BitshiftLeft2u_a, a); \
         CVE_Neon_FromVec2u(CVE_BitshiftLeft2u_b, b); \
         CVE_BitshiftLeft2u_a = vshl_u32(CVE_BitshiftLeft2u_a, CVE_BitshiftLeft2u_b); \
         CVE_Neon_ToVec2u(out, CVE_BitshiftLeft2u_a); \
        } while(0)
#else
#define CVE_BitshiftLeft2u(out, a, b) \
        do { \
         out.x = a.x << b.x; \
         out.y = a.y << b.y; \
        } while(0)
#endif

#if defined(CVE_CPU_ARM64) && defined(CVE_F32)
#define CVE_BitwiseNot2u(out, a) \
        do { \
        	uint32x2_t CVE_BitwiseNot2u_a; \
         CVE_Neon_FromVec2u(CVE_BitwiseNot2u_a, a); \
         CVE_BitwiseNot2u_a = vmvn_u32(CVE_BitwiseNot2u_a); \
         CVE_Neon_ToVec2u(out, CVE_BitwiseNot2u_a); \
        } while(0)
#else
#define CVE_BitwiseNot2u(out, a) \
        do { \
         out.x = ~a.x; \
         out.y = ~a.y; \
        } while(0)
#endif

#endif


