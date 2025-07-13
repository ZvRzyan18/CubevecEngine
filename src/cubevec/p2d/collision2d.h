/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_COLLISION2D_H
#define CVE_COLLISION2D_H

#include "cubevec/p2d/body2d.h"


typedef struct {
 CVE_Body2D *a, *b;
	CVE_Uint   collide;
	CVE_Float  depth;
	CVE_Vec2f  direction;
	CVE_Vec2f  contact[2];
	CVE_Size   contact_size;
} CVE_Manifold2D;


void __cve_collide_convex_vs_convex2d(CVE_Body2D *a, CVE_Body2D *b, 
        CVE_Vec2f* a_vertices, CVE_Vec2f* a_normals, CVE_Size a_vertices_size, 
        CVE_Vec2f* b_vertices, CVE_Vec2f* b_normals, CVE_Size b_vertices_size,
        CVE_Manifold2D *manifold
        );

void __cve_collide_convex_vs_circle2d(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Vec2f* a_vertices, CVE_Vec2f* a_normals, CVE_Size a_vertices_size, 
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       );

void __cve_collide_circle_vs_circle2d(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Float a_radius,
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       );

void __cve_collide_convex_vs_convex2d_contact(CVE_Body2D *a, CVE_Body2D *b, 
        CVE_Vec2f* a_vertices, CVE_Size a_vertices_size, 
        CVE_Vec2f* b_vertices, CVE_Size b_vertices_size,
        CVE_Manifold2D *manifold
        );

void __cve_collide_convex_vs_circle2d_contact(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Vec2f* a_vertices, CVE_Size a_vertices_size, 
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       );

void __cve_collide_circle_vs_circle2d_contact(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Float a_radius,
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       );

void __cve_collide2d(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold);

#endif

