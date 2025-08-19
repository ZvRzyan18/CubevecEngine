/*
 CubeVec Engine Core
 under MIT License.
*/


#ifndef CUBEVEC_CORE_H
#define CUBEVEC_CORE_H


#include <float.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


#if defined(_WIN32)
#define CVE_API __declspec(dllexport)
#else
#define CVE_API __attribute__((visibility("default")))
#endif



/*********************************************
 *
 *               PRIMITIVE TYPES
 *
 *********************************************/


/*
 if the size of unsigned int and float is not equal, just change 
 the unsigned int 
*/

/*macro options*/
#define CVE_F32
//#define CVE_USE_STD_MATH
//#define CVE_FORCE_CPU_INSTRUCTIONS


#if defined(CVE_F32)
typedef float         CVE_Float;
typedef unsigned int  CVE_Uint;
#elif defined(CVE_F64)
typedef double             CVE_Float;
typedef unsigned long long CVE_Uint;
#else
#error please select between CVE_F32 and CVE_F64
#endif

typedef unsigned int  CVE_Flag;
typedef long          CVE_Int;
typedef unsigned long CVE_Size;
typedef void*         CVE_Handle;



/*********************************************
 *
 *               SIZEOF ASSERT
 *
 *********************************************/

/*
 the size of unsigned int and float must be equal
 or else it will result in compile time error,
 since it uses in bit manipulation tricks for approximation
 so it should be checked 
*/
#ifndef CVE_USE_STD_MATH
typedef char __cve_assert_uint_size[sizeof(CVE_Uint) == sizeof(CVE_Float) ? 1 : -1];
#endif

/*
 allocator callbacks
*/
typedef struct {
	CVE_Handle (*allocate)(CVE_Size bytes_size);
	void (*deallocate)(CVE_Handle ptr_bytes);
} CVE_Allocator;


typedef struct {
	void (*error_msg)(const char* msg);
} CVE_ErrorHandler;

/*********************************************
 *
 *               CORE 2D
 *
 *********************************************/

enum CVE_Broadphase2D {
	CVE_BROADPHASE2D_BRUITE_FORCE = 1,
	CVE_BROADPHASE2D_SWEEP_AND_PRUNE_X = 2,
	CVE_BROADPHASE2D_SWEEP_AND_PRUNE_Y = 3,
};


enum CVE_Body2DTypes {
	CVE_BODY2D_TYPE_RECT = 1,
	CVE_BODY2D_TYPE_CIRCLE = 2,
	CVE_BODY2D_TYPE_TRIANGLE = 3,
	CVE_BODY2D_TYPE_CONVEX = 4,
};


enum CVE_BodyMovement2DTypes {
	CVE_BODY2D_MOVEMENT_TYPES_DYNAMIC = 1,
	CVE_BODY2D_MOVEMENT_TYPES_STATIC = 2,
	CVE_BODY2D_MOVEMENT_TYPES_KINEMATIC = 3,
};


enum CVE_Body2DConstraintMovement {
	CVE_BODY2D_CONSTRAINT_MOVEMENT_TYPE_X = 0b00000001,
	CVE_BODY2D_CONSTRAINT_MOVEMENT_TYPE_Y = 0b00000010,
	CVE_BODY2D_CONSTRAINT_MOVEMENT_TYPE_ROTATION = 0b00000100,
};


typedef struct {
	CVE_Uint  movement_type;
	CVE_Float pre_translate[2];
	CVE_Float pre_rotate;
	CVE_Float pre_scale[2];
	CVE_Float density;
	CVE_Float restitution;
	CVE_Float width, height;
	CVE_Float friction;
	CVE_Float linear_damping[2];
	CVE_Float angular_damping;
} CVE_CreateRectBody2D;

typedef struct {
	CVE_Uint  movement_type;
	CVE_Float pre_translate[2];
	CVE_Float pre_rotate;
	CVE_Float pre_scale;
	CVE_Float density;
	CVE_Float restitution;
	CVE_Float radius;
	CVE_Float friction;
	CVE_Float linear_damping[2];
	CVE_Float angular_damping;
} CVE_CreateCircleBody2D;

typedef struct {
	CVE_Uint  movement_type;
	CVE_Float pre_translate[2];
	CVE_Float pre_rotate;
	CVE_Float pre_scale[2];
	CVE_Float density;
	CVE_Float restitution;
	CVE_Float vertices[6];
	CVE_Float friction;
	CVE_Float linear_damping[2];
	CVE_Float angular_damping;
} CVE_CreateTriangleBody2D;

typedef struct {
	CVE_Uint  movement_type;
	CVE_Float pre_translate[2];
	CVE_Float pre_rotate;
	CVE_Float pre_scale[2];
	CVE_Float density;
	CVE_Float restitution;
	CVE_Float *vertices;
	CVE_Size  vertices_size;
	CVE_Float friction;
	CVE_Float linear_damping[2];
	CVE_Float angular_damping;
} CVE_CreateConvexBody2D;


typedef CVE_Handle CVE_BodyHandle2D;
typedef CVE_Handle CVE_World2D;
typedef CVE_Handle CVE_CollisionPipeline2D;
typedef CVE_Handle CVE_BodyPool2D;

/*********************************************
 *
 *               WORLD2D FUNCTIONS
 *
 *********************************************/

CVE_API void cveSetGlobalAllocator(CVE_Allocator* allocator);
CVE_API void cveSetGlobalErrorHandler(CVE_ErrorHandler* handler);

CVE_API void cveCreateWorld2D(CVE_World2D* world);
CVE_API void cveDestroyWorld2D(CVE_World2D world);

CVE_API void cveUpdateWorld2D(CVE_World2D world, CVE_Float time);
CVE_API void cveSetGravityWorld2D(CVE_World2D world, CVE_Float* gravity);
CVE_API void cveSetSubstepWorld2D(CVE_World2D world, CVE_Uint substep);
CVE_API void cveSetBroadphaseTypeWorld2D(CVE_World2D world, CVE_Uint type);


CVE_API void cveAddBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D* handle, CVE_Uint type, CVE_Handle ptr);
CVE_API void cveRemoveBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D handle);


/*********************************************
 *
 *               BODY2D FUNCTIONS
 *
 *********************************************/

CVE_API void cveGetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr);
CVE_API void cveSetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);
CVE_API void cveGetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr);
CVE_API void cveSetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);

CVE_API void cveAddForceBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);
CVE_API void cveAddTorqueBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);

CVE_API void cveAddLinearImpulseBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);
CVE_API void cveAddRotationalImpulseBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);

#ifdef __cplusplus
}
#endif

#endif

