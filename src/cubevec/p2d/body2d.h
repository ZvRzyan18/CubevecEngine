/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_BODY2D_H
#define CVE_BODY2D_H


#include "cubevec/core.h"
#include "cubevec/math/math.h"


/*********************************************
 *
 *               BODY CORE INTERNAL 
 *
 *********************************************/


typedef struct CVE_BodyInternalPart2D CVE_BodyInternalPart2D;
struct CVE_BodyInternalPart2D {
	CVE_Flag  body_type;
	CVE_Flag  movement_type;
	CVE_Flag  constraint;
	
	CVE_Float is_resting;
	CVE_Float rest_time;
	

	CVE_Vec2f position;
	CVE_Float rotation;
	CVE_Vec2f velocity;
	CVE_Float omega;
	CVE_Vec2f force;
	CVE_Float torque;
	CVE_Vec2f centroid;
	CVE_Float density;
	CVE_Float restitution;
 CVE_Float area;
	CVE_Float mass;
	CVE_Float inv_mass;
	CVE_Float rotational_inertia;
	CVE_Float inv_rotational_inertia;
	
	CVE_Vec2f logarithmic_linear_damping;
	CVE_Float logarithmic_angular_damping;
	
	CVE_Float friction;
	CVE_Vec2f aabb[2];
	void      (*update)(void* self, CVE_Float time, CVE_Vec2f gravity);
	CVE_BodyInternalPart2D* next;
	CVE_BodyInternalPart2D* prev;
};


/*********************************************
 *
 *               SPECIFIC BODY TYPE
 *
 *********************************************/

typedef struct {
	CVE_BodyInternalPart2D components;
	CVE_Vec2f              shape_size; //x : width, y : height
	CVE_Vec2f              transformed_vertices[4];
	CVE_Vec2f              normals[4];
} CVE_RectBody2D;

typedef struct {
	CVE_BodyInternalPart2D components;
	CVE_Float              radius;
} CVE_CircleBody2D;

typedef struct {
	CVE_BodyInternalPart2D components;
	CVE_Vec2f              transformed_vertices[3];
	CVE_Vec2f              normals[3];
} CVE_TriangleBody2D;

typedef struct {
	CVE_BodyInternalPart2D components;
	CVE_Vec2f              *vertices;
	CVE_Vec2f              *transformed_vertices;
	CVE_Vec2f              *normals;
 CVE_Size               vertices_size;
} CVE_ConvexBody2D;

/*********************************************
 *
 *               GENERIC BODY2D
 *
 *********************************************/

typedef union {
	CVE_Uint               body_type;
	CVE_BodyInternalPart2D components;
	CVE_RectBody2D         rect_body;
	CVE_CircleBody2D       circle_body;
	CVE_TriangleBody2D     triangle_body;
	CVE_ConvexBody2D       convex_body;
} CVE_Body2D;

/* this will asign a function depends on its type */
void __cve_init_body2d(CVE_Body2D* body2d);


#endif

