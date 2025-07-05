/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/collision2d.h"



void __cve_collide_convex_vs_convex2d(CVE_Body2D *a, CVE_Body2D *b, 
        CVE_Vec2f* a_vertices, CVE_Vec2f* a_normals, CVE_Size a_vertices_size, 
        CVE_Vec2f* b_vertices, CVE_Vec2f* b_normals, CVE_Size b_vertices_size,
        CVE_Manifold2D *manifold
        ) {

 if(((
    a->components.aabb[0].x > b->components.aabb[1].x 
 || a->components.aabb[1].x < b->components.aabb[0].x) ||
   (
    a->components.aabb[0].y > b->components.aabb[1].y 
 || a->components.aabb[1].y < b->components.aabb[0].y)
 )) {
  manifold->collide = 0;
  return;    	
 }

 CVE_Size i, j;
 CVE_Vec2f a_minmax, b_minmax, diff, dx, dy, centroid;
 CVE_Float cast, closest;
 
 manifold->a = a;
 manifold->b = b;
 manifold->depth = CVE_HUGE_FLOAT;
 i = 0;
 while(a_vertices_size - i) {
 	
  const	CVE_Vec2f normal = a_normals[i];
 	
 	a_minmax.x = CVE_HUGE_FLOAT;
 	a_minmax.y = -CVE_HUGE_FLOAT;
 	j = 0;
 	while(a_vertices_size - j) {
 		CVE_Dot2f(cast, normal, a_vertices[j]);
 		CVE_Min(a_minmax.x, a_minmax.x, cast);
 		CVE_Max(a_minmax.y, a_minmax.y, cast);
 		j++;
 	}
 	
 	b_minmax.x = CVE_HUGE_FLOAT;
 	b_minmax.y = -CVE_HUGE_FLOAT;
 	j = 0;
 	while(b_vertices_size - j) {
 		CVE_Dot2f(cast, normal, b_vertices[j]);
 		CVE_Min(b_minmax.x, b_minmax.x, cast);
 		CVE_Max(b_minmax.y, b_minmax.y, cast);
 		j++;
 	}
 	
 	
  dy.x = b_minmax.y;
  dy.y = a_minmax.y;
  dx.x = a_minmax.x;
  dx.y = b_minmax.x;
  CVE_Sub2f(diff, dy, dx);
  CVE_Min(closest, diff.x, diff.y);
  if(closest < manifold->depth) {
   manifold->depth = closest;
   manifold->direction = normal;
  }
 	
 	i++;
 }

 i = 0;
 while(b_vertices_size - i) {
 	
  const	CVE_Vec2f normal = b_normals[i];
 	
 	a_minmax.x = CVE_HUGE_FLOAT;
 	a_minmax.y = -CVE_HUGE_FLOAT;
 	j = 0;
 	while(a_vertices_size - j) {
 		CVE_Dot2f(cast, normal, a_vertices[j]);
 		CVE_Min(a_minmax.x, a_minmax.x, cast);
 		CVE_Max(a_minmax.y, a_minmax.y, cast);
 		j++;
 	}
 	
 	b_minmax.x = CVE_HUGE_FLOAT;
 	b_minmax.y = -CVE_HUGE_FLOAT;
 	j = 0;
 	while(b_vertices_size - j) {
 		CVE_Dot2f(cast, normal, b_vertices[j]);
 		CVE_Min(b_minmax.x, b_minmax.x, cast);
 		CVE_Max(b_minmax.y, b_minmax.y, cast);
 		j++;
 	}
 	
 	
  dy.x = b_minmax.y;
  dy.y = a_minmax.y;
  dx.x = a_minmax.x;
  dx.y = b_minmax.x;
  CVE_Sub2f(diff, dy, dx);
  CVE_Min(closest, diff.x, diff.y);
  if(closest < manifold->depth) {
   manifold->depth = closest;
   manifold->direction = normal;
  }
 	
 	i++;
 }
 
 CVE_Sub2f(centroid, b->components.centroid, a->components.centroid);
 CVE_Dot2f(cast, centroid, manifold->direction);
 if(cast < 0.0)
 	CVE_Negate2f(manifold->direction, manifold->direction);
 manifold->collide = 1;
}




void __cve_collide2d(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold) {
 __cve_collide_convex_vs_convex2d(a, b, 
   a->rect_body.transformed_vertices, a->rect_body.normals, 4,
   b->rect_body.transformed_vertices, b->rect_body.normals, 4,
   manifold
   );
}


        