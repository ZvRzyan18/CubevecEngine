/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/collision2d.h"


static void CVE_PointSegmentDistance(CVE_Vec2f p, CVE_Vec2f a, CVE_Vec2f b, CVE_Float* dist_squared, CVE_Vec2f* contact);

/*
	CVE_BODY2D_TYPE_RECT = 1,
	CVE_BODY2D_TYPE_CIRCLE = 2,
	CVE_BODY2D_TYPE_TRIANGLE = 3,
	CVE_BODY2D_TYPE_CONVEX = 4,
*/

static void Rect_Vs_Rect(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold);
static void Rect_Vs_Circle(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold);

static void Circle_Vs_Rect(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold);
static void Circle_Vs_Circle(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold);


void __cve_narrowphase_table_init(CVE_NarrowphaseTable *table) {
	table->functions[CVE_BODY2D_TYPE_RECT][CVE_BODY2D_TYPE_RECT] = Rect_Vs_Rect;
	table->functions[CVE_BODY2D_TYPE_RECT][CVE_BODY2D_TYPE_CIRCLE] = Rect_Vs_Circle;

	table->functions[CVE_BODY2D_TYPE_CIRCLE][CVE_BODY2D_TYPE_RECT] = Circle_Vs_Rect;
	table->functions[CVE_BODY2D_TYPE_CIRCLE][CVE_BODY2D_TYPE_CIRCLE] = Circle_Vs_Circle;

}


/*********************************************
 *
 *               SHAPE VS SHAPE COLLISION
 *
 *********************************************/
/*
 for loop is much better for iterating rect vertices and normals since it could be unrolled by compiler 
 easily than a while loop.
*/
static void Rect_Vs_Rect(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold) {
 CVE_Vec2f a_minmax, b_minmax, diff, dx, dy, centroid, *begin_normal, *end_normal, *begin_vertices, *end_vertices;
 CVE_Float cast, closest;
 
 CVE_Uint i, j;
 
 manifold->a = a;
 manifold->b = b;
 manifold->depth = CVE_HUGE_FLOAT;
 manifold->collide = 0;
 
 begin_normal = a->rect_body.normals;
 end_normal = begin_normal + 4;
 
 /*
 while(begin_normal < end_normal) {
 */
 for(i = 0; i < 4; i++) {
  const CVE_Vec2f normal = *(begin_normal++);

  a_minmax.x = CVE_HUGE_FLOAT;
  a_minmax.y = -CVE_HUGE_FLOAT;
  begin_vertices = a->rect_body.transformed_vertices;
  end_vertices = begin_vertices + 4;
  
  /*
  while(begin_vertices < end_vertices) {
  */
  for(j = 0; j < 4; j++) {
   const CVE_Vec2f curr_vertices = (*(begin_vertices++));
   CVE_Dot2f(cast, normal, curr_vertices);
   CVE_Min(a_minmax.x, a_minmax.x, cast);
   CVE_Max(a_minmax.y, a_minmax.y, cast);
  }
 	
  b_minmax.x = CVE_HUGE_FLOAT;
  b_minmax.y = -CVE_HUGE_FLOAT;
  begin_vertices = b->rect_body.transformed_vertices;
  end_vertices = begin_vertices + 4;

  /*
  while(begin_vertices < end_vertices) {
  */
  for(j = 0; j < 4; j++) {
   const CVE_Vec2f curr_vertices = (*(begin_vertices++));
   CVE_Dot2f(cast, normal, curr_vertices);
   CVE_Min(b_minmax.x, b_minmax.x, cast);
   CVE_Max(b_minmax.y, b_minmax.y, cast);
 	}
 	
  if((a_minmax.y <= b_minmax.x) || (b_minmax.y <= a_minmax.x)) {
   manifold->collide = 0;
   return;
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
 	
 }


 begin_normal = b->rect_body.normals;
 end_normal = begin_normal + 4;
 
/*
 while(begin_normal < end_normal) {
*/
 for(i = 0; i < 4; i++) {
  const CVE_Vec2f normal = *(begin_normal++);

  a_minmax.x = CVE_HUGE_FLOAT;
  a_minmax.y = -CVE_HUGE_FLOAT;
  begin_vertices = a->rect_body.transformed_vertices;
  end_vertices = begin_vertices + 4;
  
 /*
  while(begin_vertices < end_vertices) {
 */
  for(j = 0; j < 4; j++) {
   const CVE_Vec2f curr_vertices = (*(begin_vertices++));
   CVE_Dot2f(cast, normal, curr_vertices);
   CVE_Min(a_minmax.x, a_minmax.x, cast);
   CVE_Max(a_minmax.y, a_minmax.y, cast);
  }
 	
  b_minmax.x = CVE_HUGE_FLOAT;
  b_minmax.y = -CVE_HUGE_FLOAT;
  begin_vertices = b->rect_body.transformed_vertices;
  end_vertices = begin_vertices + 4;

 /*
  while(begin_vertices < end_vertices) {
 */
  for(j = 0; j < 4; j++) {
   const CVE_Vec2f curr_vertices = (*(begin_vertices++));
   CVE_Dot2f(cast, normal, curr_vertices);
   CVE_Min(b_minmax.x, b_minmax.x, cast);
   CVE_Max(b_minmax.y, b_minmax.y, cast);
 	}
 	
  if((a_minmax.y <= b_minmax.x) || (b_minmax.y <= a_minmax.x)) {
   manifold->collide = 0;
   return;
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
 	
 }

 
 CVE_Sub2f(centroid, b->components.centroid, a->components.centroid);
 CVE_Dot2f(cast, centroid, manifold->direction);
 if(cast < 0.0)
  CVE_Negate2f(manifold->direction, manifold->direction);
 manifold->collide = 1;

/*
 find contact points
*/

 CVE_Float dist = CVE_HUGE_FLOAT;
 CVE_Vec2f m_contact1, m_contact2, *begin_vertices1, *end_vertices1;
 CVE_Size m_contact_count;

 m_contact_count = 0;
 /*
  polygon a
 */
 begin_vertices = a->rect_body.transformed_vertices;
 end_vertices = begin_vertices + 4;

 /*
 while(begin_vertices < end_vertices) {
 */
 for(i = 0; i < 4; i++) {
  const CVE_Vec2f p = *(begin_vertices++);

  begin_vertices1 = b->rect_body.transformed_vertices;
  end_vertices1 = begin_vertices1 + 4;

  /*
   while(begin_vertices1 < end_vertices1) {
  */
  for(j = 0; j < 4; j++) {
   const CVE_Vec2f aa = *(begin_vertices1++);
   const CVE_Vec2f bb = (begin_vertices1 == end_vertices1) ? b->rect_body.transformed_vertices[0] : *(begin_vertices1);
	 	
   CVE_Float dist_tmp;
   CVE_Uint is_equals, is_equals1;
   CVE_Vec2f contact_tmp;
   CVE_PointSegmentDistance(p, aa, bb, &dist_tmp, &contact_tmp);
   CVE_ApproxEquals(is_equals, dist_tmp, dist);
  if(is_equals) {
   CVE_ApproxEquals(is_equals, contact_tmp.x, m_contact1.x);
   CVE_ApproxEquals(is_equals1, contact_tmp.y, m_contact1.y);
   if(!(is_equals && is_equals1)) {
    m_contact2 = contact_tmp;
    m_contact_count = 2;
   }
  }
  if(dist_tmp < dist) {
   dist = dist_tmp;
   m_contact_count = 1;
   m_contact1 = contact_tmp;
  }

  }
 }

 /*
  polygon b
 */
 begin_vertices = b->rect_body.transformed_vertices;
 end_vertices = begin_vertices + 4;

 /*
  while(begin_vertices < end_vertices) {
 */
 for(i = 0; i < 4; i++) {
  const CVE_Vec2f p = *(begin_vertices++);

  begin_vertices1 = a->rect_body.transformed_vertices;
  end_vertices1 = begin_vertices1 + 4;

  /*
   while(begin_vertices1 < end_vertices1) {
  */
  for(j = 0; j < 4; j++) {
   const CVE_Vec2f aa = *(begin_vertices1++);
   const CVE_Vec2f bb = (begin_vertices1 == end_vertices1) ? a->rect_body.transformed_vertices[0] : *(begin_vertices1);
	 	
   CVE_Float dist_tmp;
   CVE_Uint is_equals, is_equals1;
   CVE_Vec2f contact_tmp;
   CVE_PointSegmentDistance(p, aa, bb, &dist_tmp, &contact_tmp);
   CVE_ApproxEquals(is_equals, dist_tmp, dist);
  if(is_equals) {
   CVE_ApproxEquals(is_equals, contact_tmp.x, m_contact1.x);
   CVE_ApproxEquals(is_equals1, contact_tmp.y, m_contact1.y);
   if(!(is_equals && is_equals1)) {
    m_contact2 = contact_tmp;
    m_contact_count = 2;
   }
  }
  if(dist_tmp < dist) {
   dist = dist_tmp;
   m_contact_count = 1;
   m_contact1 = contact_tmp;
  }

  }
 }
	
 manifold->contact[0] = m_contact1;
 manifold->contact[1] = m_contact2;
 manifold->contact_size = m_contact_count;
}

/*
 rect vs circle
*/
static void Rect_Vs_Circle(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold) {
 CVE_Vec2f a_minmax, b_minmax, diff, dx, dy, centroid, edge_to_circle, *begin_normal, *begin_vertices;
 CVE_Vec2f *end_vertices, *end_normal;
 CVE_Float cast, closest, closest_to_b;
 
 CVE_Uint i, j;
 
 manifold->a = a;
 manifold->b = b;
 manifold->depth = CVE_HUGE_FLOAT;
 manifold->collide = 0;
 
 closest_to_b = CVE_HUGE_FLOAT;
 begin_normal = a->rect_body.normals;
 end_normal = begin_normal + 4;
 /*
 while(begin_normal < end_normal) {
 */
 for(i = 0; i < 4; i++) {
 	
  const	CVE_Vec2f normal = *(begin_normal++);
 	
  a_minmax.x = CVE_HUGE_FLOAT;
  a_minmax.y = -CVE_HUGE_FLOAT;
  
  begin_vertices = a->rect_body.transformed_vertices;
  end_vertices = begin_vertices + 4;
  /*
  while(begin_vertices < end_vertices) {
  */
  for(j = 0; j < 4; j++) {
   const CVE_Vec2f curr_vertices = (*(begin_vertices++));
   CVE_Dot2f(cast, normal, curr_vertices);
   CVE_Min(a_minmax.x, a_minmax.x, cast);
   CVE_Max(a_minmax.y, a_minmax.y, cast);
  }
  	
  do {
   CVE_Vec2f dir, p1, p2, projected, vec_radius;
   
   CVE_ScalarToVector2f(vec_radius, b->circle_body.radius);
   CVE_Mul2f(dir, vec_radius, normal);
   CVE_Add2f(p1, b->components.centroid, dir);
   CVE_Sub2f(p2, b->components.centroid, dir);
   CVE_Dot2f(projected.x, p1, normal);
   CVE_Dot2f(projected.y, p2, normal);
   CVE_Min(b_minmax.x, projected.x, projected.y);
   CVE_Max(b_minmax.y, projected.x, projected.y);
  } while(0);
 	
  if((a_minmax.y <= b_minmax.x) || (b_minmax.y <= a_minmax.x)) {
   manifold->collide = 0;
   return;
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
  
  CVE_Float dist;
  CVE_Vec2f edge;
  CVE_Sub2f(edge, a->rect_body.transformed_vertices[begin_normal - a->rect_body.normals], b->components.centroid);
  CVE_Dot2f(dist, edge, edge);
  if(dist < closest_to_b) {
   closest_to_b = dist;
   edge_to_circle = edge;
  }
 	
 }
 
 
 CVE_Vec2f normal;
 CVE_Normalize2f(normal, edge_to_circle);

 a_minmax.x = CVE_HUGE_FLOAT;
 a_minmax.y = -CVE_HUGE_FLOAT;
 begin_vertices = a->rect_body.transformed_vertices;
 end_vertices = begin_vertices + 4;
 /*
 while(begin_vertices < end_vertices) {
 */
 for(j = 0; j < 4; j++) {
  const CVE_Vec2f curr_vertices = (*(begin_vertices++));
  CVE_Dot2f(cast, normal, curr_vertices);
  CVE_Min(a_minmax.x, a_minmax.x, cast);
  CVE_Max(a_minmax.y, a_minmax.y, cast);
 }
 	 	
 do {
  CVE_Vec2f dir, p1, p2, projected, vec_radius;
   
  CVE_ScalarToVector2f(vec_radius, b->circle_body.radius);
  CVE_Mul2f(dir, vec_radius, normal);
  CVE_Add2f(p1, b->components.centroid, dir);
  CVE_Sub2f(p2, b->components.centroid, dir);
  CVE_Dot2f(projected.x, p1, normal);
  CVE_Dot2f(projected.y, p2, normal);
  CVE_Min(b_minmax.x, projected.x, projected.y);
  CVE_Max(b_minmax.y, projected.x, projected.y);
 } while(0);

 if((a_minmax.y <= b_minmax.x) || (b_minmax.y <= a_minmax.x)) {
  manifold->collide = 0;
  return;
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
  
 CVE_Sub2f(centroid, b->components.centroid, a->components.centroid);
 CVE_Dot2f(cast, centroid, manifold->direction);
 if(cast < 0.0)
  CVE_Negate2f(manifold->direction, manifold->direction);
 manifold->collide = 1;

/*
 find contact points
*/
 CVE_Float dist = CVE_HUGE_FLOAT;
 CVE_Vec2f m_contact;
 begin_vertices = a->rect_body.transformed_vertices;
 end_vertices = begin_vertices + 4;

/*
 while(begin_vertices < end_vertices) {
*/
 for(i = 0; i < 4; i++) {
  const CVE_Vec2f p1 = *(begin_vertices++);
  const CVE_Vec2f p2 = (begin_vertices == end_vertices) ? a->rect_body.transformed_vertices[0] : *begin_vertices;
		
  CVE_Float dist_tmp;
  CVE_Vec2f contact_tmp;
  CVE_PointSegmentDistance(b->components.centroid, p1, p2, &dist_tmp, &contact_tmp);
  if(dist_tmp < dist) {
   dist = dist_tmp;
   m_contact = contact_tmp;
  }
 }
 manifold->contact_size = 1;
 manifold->contact[0] = m_contact;
}

static void Circle_Vs_Rect(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold) {
	Rect_Vs_Circle(b, a, manifold);
}


static void Circle_Vs_Circle(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold) {
 manifold->a = a;
 manifold->b = b;
 manifold->depth = CVE_HUGE_FLOAT;
 manifold->collide = 0;
 
 CVE_Vec2f dir, inv_len_vec;
 CVE_Float dist, sum_rad, inv_len;

 CVE_Sub2f(dir, b->components.centroid, a->components.centroid);
 CVE_Dot2f(dist, dir, dir);
 sum_rad = a->circle_body.radius + b->circle_body.radius;
 if(dist >= (sum_rad * sum_rad)) {
  manifold->collide = 0;
  return;
 }
 
 CVE_InvSqrt(inv_len, dist);
 CVE_ScalarToVector2f(inv_len_vec, inv_len);
 CVE_Mul2f(manifold->direction, dir, inv_len_vec);
 manifold->depth =  sum_rad - (dist * inv_len);
 manifold->collide = 1;
/*
 contact points
*/
 CVE_Vec2f rad_vec;
 CVE_ScalarToVector2f(rad_vec, a->circle_body.radius);
 CVE_Sub2f(dir, b->components.centroid, a->components.centroid);
 CVE_Normalize2f(dir, dir);
 CVE_Fma2f(manifold->contact[0], dir, rad_vec, a->components.centroid);
 manifold->contact_size = 1;
}


/*
 private function for point segement distance
*/
static void CVE_PointSegmentDistance(CVE_Vec2f p, CVE_Vec2f a, CVE_Vec2f b, CVE_Float* dist_squared, CVE_Vec2f* contact) {
 CVE_Vec2f ab, ap, d_vec, diff;
 CVE_Float proj, len_squared, d;
 
 CVE_Sub2f(ab, b, a);
 CVE_Sub2f(ap, p, a);
	
 CVE_Dot2f(proj, ab, ap);
 CVE_Dot2f(len_squared, ab, ab);
 d = proj / len_squared;
	
 if(d <= 0.0)
  *contact = a;
 else if(d >= 1.0)
  *contact = b;
 else {
  CVE_ScalarToVector2f(d_vec, d);
  CVE_Fma2f((*contact), ab, d_vec, a);
 }
 CVE_Sub2f(diff, p, (*contact));
 CVE_Dot2f((*dist_squared), diff, diff);
}

        