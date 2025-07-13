/*
 CubeVec Engine Core
 under MIT License.
*/


#ifndef CUBEVEC_CORE_H
#define CUBEVEC_CORE_H


#include <float.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
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
typedef float         CVE_Float;
typedef unsigned int  CVE_Uint;
typedef unsigned long CVE_Size;
typedef void*         CVE_Handle;



/*********************************************
 *
 *               SIZEOF ASSERT
 *
 *********************************************/

/*
 the size of unsigned int and float must be equal
 or else it will result in compile time error
*/
typedef char __cve_assert_uint_size[sizeof(CVE_Uint) == sizeof(CVE_Float) ? 1 : -1];
typedef char __cve_assert_float_size[sizeof(CVE_Float) == 4 ? 1 : -1];


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

enum CVE_Body2DTypes {
	CVE_BODY2D_TYPE_RECT = 1,
	CVE_BODY2D_TYPE_CIRCLE = 2,
	CVE_BODY2D_TYPE_TRIANGLE = 3,
	CVE_BODY2D_TYPE_CONVEX = 4,
};

enum CVE_BodyMovement2DTypes {
	CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC = 1,
	CVE_BODY_MOVEMENT2D_TYPES_STATIC = 2,
	CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC = 3,
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

void cveSetGlobalAllocator(CVE_Allocator* allocator);
void cveSetGlobalErrorHandler(CVE_ErrorHandler* handler);

void cveCreateWorld2D(CVE_World2D* world);
void cveDestroyWorld2D(CVE_World2D world);

void cveUpdateWorld2D(CVE_World2D world, CVE_Float time);
void cveSetGravityWorld2D(CVE_World2D world, CVE_Float* gravity);
void cveSetIterationWorld2D(CVE_World2D world, CVE_Uint iteration);
void cveSetEpsilonWorld2D(CVE_World2D world, CVE_Float epsilon);


void cveAddBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D* handle, CVE_Uint type, CVE_Handle ptr);
void cveRemoveBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D handle);


/*********************************************
 *
 *               BODY2D FUNCTIONS
 *
 *********************************************/

void cveGetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr);
void cveSetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);
void cveGetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr);
void cveSetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr);


#ifdef __cplusplus
}
#endif

#endif

