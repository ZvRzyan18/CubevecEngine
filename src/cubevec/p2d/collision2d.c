/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/collision2d.h"

/*
 SAT collision checks
*/
void __cve_collide_convex_vs_convex2d(CVE_Body2D *a, CVE_Body2D *b, 
        CVE_Vec2f* a_vertices, CVE_Vec2f* a_normals, CVE_Size a_vertices_size, 
        CVE_Vec2f* b_vertices, CVE_Vec2f* b_normals, CVE_Size b_vertices_size,
        CVE_Manifold2D *manifold
        ) {
/*
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
*/
 CVE_Size i, j;
 CVE_Vec2f a_minmax, b_minmax, diff, dx, dy, centroid;
 CVE_Float cast, closest;
 
 manifold->a = a;
 manifold->b = b;
 manifold->depth = CVE_HUGE_FLOAT;
 manifold->collide = 0;
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
 	
 	i++;
 }
 
 CVE_Sub2f(centroid, b->components.centroid, a->components.centroid);
 CVE_Dot2f(cast, centroid, manifold->direction);
 if(cast < 0.0)
 	CVE_Negate2f(manifold->direction, manifold->direction);
 manifold->collide = 1;
 
}


void __cve_collide_convex_vs_circle2d(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Vec2f* a_vertices, CVE_Vec2f* a_normals, CVE_Size a_vertices_size, 
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       ) {
/*
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
*/
 CVE_Size i, j;
 CVE_Vec2f a_minmax, b_minmax, diff, dx, dy, centroid, edge_to_circle;
 CVE_Float cast, closest, closest_to_b;
 
 manifold->a = a;
 manifold->b = b;
 manifold->depth = CVE_HUGE_FLOAT;
 manifold->collide = 0;
 
 closest_to_b = CVE_HUGE_FLOAT;
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
  	
 	do {
   CVE_Vec2f dir, p1, p2, projected, vec_radius;
   
   CVE_ScalarToVector2f(vec_radius, b_radius);
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
  CVE_Sub2f(edge, a_vertices[i], b->components.centroid);
  CVE_Dot2f(dist, edge, edge);
  if(dist < closest_to_b) {
  	closest_to_b = dist;
  	edge_to_circle = edge;
  }
 	
 	i++;
 }
 
 
 CVE_Vec2f normal;
 CVE_Normalize2f(normal, edge_to_circle);

	a_minmax.x = CVE_HUGE_FLOAT;
 a_minmax.y = -CVE_HUGE_FLOAT;
 j = 0;
 while(a_vertices_size - j) {
 	CVE_Dot2f(cast, normal, a_vertices[j]);
 	CVE_Min(a_minmax.x, a_minmax.x, cast);
 	CVE_Max(a_minmax.y, a_minmax.y, cast);
 	j++;
	}
 	 	
	do {
  CVE_Vec2f dir, p1, p2, projected, vec_radius;
   
  CVE_ScalarToVector2f(vec_radius, b_radius);
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
}



void __cve_collide_circle_vs_circle2d(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Float a_radius,
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       ) {
/*
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
*/
 manifold->a = a;
 manifold->b = b;
 manifold->depth = CVE_HUGE_FLOAT;
 manifold->collide = 0;
 
 CVE_Vec2f dir, inv_len_vec;
 CVE_Float dist, sum_rad, inv_len;

 CVE_Sub2f(dir, b->components.centroid, a->components.centroid);
 CVE_Dot2f(dist, dir, dir);
 sum_rad = a_radius + b_radius;
 if(dist >= (sum_rad * sum_rad)) {
  manifold->collide = 0;
  return;
 }
 
 CVE_InvSqrt(inv_len, dist);
 CVE_ScalarToVector2f(inv_len_vec, inv_len);
 CVE_Mul2f(manifold->direction, dir, inv_len_vec);
 manifold->depth =  sum_rad - (dist * inv_len);
 manifold->collide = 1;
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



void __cve_collide_convex_vs_convex2d_contact(CVE_Body2D *a, CVE_Body2D *b, 
        CVE_Vec2f* a_vertices, CVE_Size a_vertices_size, 
        CVE_Vec2f* b_vertices, CVE_Size b_vertices_size,
        CVE_Manifold2D *manifold
        ) {

 CVE_Float dist = CVE_HUGE_FLOAT;
 CVE_Vec2f m_contact1, m_contact2;
 CVE_Size m_contact_count;

 m_contact_count = 0;
 /*
  polygon a
 */
	for(CVE_Size x = 0; x < a_vertices_size; x++) {
	 const CVE_Vec2f p = a_vertices[x];
  for(CVE_Size y = 0; y < b_vertices_size; y++) {
	 	const CVE_Vec2f aa = b_vertices[y];
	 	const CVE_Vec2f bb = b_vertices[(y+1) % b_vertices_size];
	 	
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
	for(CVE_Size x = 0; x < b_vertices_size; x++) {
	 const CVE_Vec2f p = b_vertices[x];
  for(CVE_Size y = 0; y < a_vertices_size; y++) {
	 	const CVE_Vec2f aa = a_vertices[y];
	 	const CVE_Vec2f bb = a_vertices[(y+1) % a_vertices_size];
	 	
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



void __cve_collide_convex_vs_circle2d_contact(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Vec2f* a_vertices, CVE_Size a_vertices_size, 
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       ) {
	CVE_Float dist = CVE_HUGE_FLOAT;
	CVE_Vec2f m_contact;
	for(CVE_Size i = 0; i < a_vertices_size; i++) {
		const CVE_Vec2f p1 = a_vertices[i];
		const CVE_Vec2f p2 = a_vertices[(i+1) % a_vertices_size];
		
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


void __cve_collide_circle_vs_circle2d_contact(CVE_Body2D *a, CVE_Body2D *b,
        CVE_Float a_radius,
        CVE_Float b_radius,
        CVE_Manifold2D *manifold
       ) {
	CVE_Vec2f dir, rad_vec;
	CVE_ScalarToVector2f(rad_vec, a->circle_body.radius);
	CVE_Sub2f(dir, b->components.centroid, a->components.centroid);
	CVE_Normalize2f(dir, dir);
 CVE_Fma2f(manifold->contact[0], dir, rad_vec, a->components.centroid);
 manifold->contact_size = 1;
}


/*
 generic body collide function
*/
void __cve_collide2d(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold) {
 
 switch(a->components.body_type) {
 	case CVE_BODY2D_TYPE_RECT:

   switch(b->components.body_type) {
   	case CVE_BODY2D_TYPE_RECT: /*rect vs rect*/
     __cve_collide_convex_vs_convex2d(a, b, 
       a->rect_body.transformed_vertices, a->rect_body.normals, 4,
       b->rect_body.transformed_vertices, b->rect_body.normals, 4,
       manifold
     );
     if(!manifold->collide) {
      manifold->contact_size = 0;
      return;
     }
     __cve_collide_convex_vs_convex2d_contact(a, b, 
       a->rect_body.transformed_vertices, 4,
       b->rect_body.transformed_vertices, 4,
       manifold
     );
   	break;
    case CVE_BODY2D_TYPE_CIRCLE: /*rect vs circle*/
     __cve_collide_convex_vs_circle2d(a, b, 
       a->rect_body.transformed_vertices, a->rect_body.normals, 4,
       b->circle_body.radius,
       manifold
     );
     if(!manifold->collide) {
      manifold->contact_size = 0;
      return;
     }
     __cve_collide_convex_vs_circle2d_contact(a, b, 
       a->rect_body.transformed_vertices, 4,
       b->circle_body.radius,
       manifold
     );
    break;
    case CVE_BODY2D_TYPE_TRIANGLE: /*rect vs triangle*/
    break;
    case CVE_BODY2D_TYPE_CONVEX: /*rect vs convex*/
    break;
   }

 	break;
  case CVE_BODY2D_TYPE_CIRCLE:

   switch(b->components.body_type) {
   	case CVE_BODY2D_TYPE_RECT: /*circle vs rect*/
     __cve_collide_convex_vs_circle2d(b, a, 
       b->rect_body.transformed_vertices, b->rect_body.normals, 4,
       a->circle_body.radius,
       manifold
     );
     if(!manifold->collide) {
      manifold->contact_size = 0;
      return;
     }
     __cve_collide_convex_vs_circle2d_contact(b, a, 
       b->rect_body.transformed_vertices, 4,
       a->circle_body.radius,
       manifold
     );
   	break;
    case CVE_BODY2D_TYPE_CIRCLE: /*circle vs circle*/
     __cve_collide_circle_vs_circle2d(a, b,
       a->circle_body.radius, 
       b->circle_body.radius,
       manifold
     );
     if(!manifold->collide) {
      manifold->contact_size = 0;
      return;
     }
     __cve_collide_circle_vs_circle2d_contact(a, b,
       a->circle_body.radius, 
       b->circle_body.radius,
       manifold
     );
    break;
    case CVE_BODY2D_TYPE_TRIANGLE: /*circle vs triangle*/
    break;
    case CVE_BODY2D_TYPE_CONVEX: /*circle vs convex*/
    break;
   }
  
  break;
  case CVE_BODY2D_TYPE_TRIANGLE:

   switch(b->components.body_type) {
   	case CVE_BODY2D_TYPE_RECT: /*triangle vs rect*/
   	break;
    case CVE_BODY2D_TYPE_CIRCLE: /*triangle vs circle*/
    break;
    case CVE_BODY2D_TYPE_TRIANGLE: /*triangle vs triangle*/
    break;
    case CVE_BODY2D_TYPE_CONVEX: /*triangle vs convex*/
    break;
   }
   
  break;
  case CVE_BODY2D_TYPE_CONVEX:

   switch(b->components.body_type) {
   	case CVE_BODY2D_TYPE_RECT: /*convex vs rect*/
   	break;
    case CVE_BODY2D_TYPE_CIRCLE: /*convex vs circle*/
    break;
    case CVE_BODY2D_TYPE_TRIANGLE: /*convex vs triangle*/
    break;
    case CVE_BODY2D_TYPE_CONVEX: /*convex vs convex*/
    break;
   }
   
  break;
 }


}


        