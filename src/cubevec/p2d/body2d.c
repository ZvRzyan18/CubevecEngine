/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/body2d.h"



extern CVE_ErrorHandler __cve_global_error_handler;


/*********************************************
 *
 *               PRIVATE FUNCTIONS
 *
 *********************************************/

static void CVE_Update_Nothing(void* self, CVE_Float time);

static void CVE_Update_RectBody2D_Dynamic(CVE_RectBody2D* self, CVE_Float time);
static void CVE_Update_CircleBody2D_Dynamic(CVE_CircleBody2D* self, CVE_Float time);
static void CVE_Update_TriangleBody2D_Dynamic(CVE_TriangleBody2D* self, CVE_Float time);
static void CVE_Update_ConvexBody2D_Dynamic(CVE_ConvexBody2D* self, CVE_Float time);


static void CVE_Init_RectBody2D(CVE_RectBody2D* rect_body);
static void CVE_Init_CircleBody2D(CVE_CircleBody2D* circle_body);
static void CVE_Init_TriangleBody2D(CVE_TriangleBody2D* triangle_body);
static void CVE_Init_ConvexBody2D(CVE_ConvexBody2D* convex_body);



/*********************************************
 *
 *               GENERIC INIT
 *
 *********************************************/


void __cve_init_body2d(CVE_Body2D* body2d) {
	switch(body2d->body_type) {
		case CVE_BODY2D_TYPE_RECT:
		
		 CVE_Init_RectBody2D(&body2d->rect_body);
		 
		 switch(body2d->components.movement_type) {
		 	case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_RectBody2D_Dynamic;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:
		 	break;
		 	default:
		 	 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid movement type.");
		 	break;
		 }
		 
		 
		break;
		case CVE_BODY2D_TYPE_CIRCLE:

		 CVE_Init_CircleBody2D(&body2d->circle_body);

		 switch(body2d->components.movement_type) {
		 	case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_CircleBody2D_Dynamic;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:
		 	break;
		 	default:
		 	 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid movement type.");
		 	break;
		 }
		 
		break;
		case CVE_BODY2D_TYPE_TRIANGLE:

		 CVE_Init_TriangleBody2D(&body2d->triangle_body);

		 switch(body2d->components.movement_type) {
		 	case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_TriangleBody2D_Dynamic;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:
		 	break;
		 	default:
		 	 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid movement type.");
		 	break;
		 }

		break;
		case CVE_BODY2D_TYPE_CONVEX:

		 CVE_Init_ConvexBody2D(&body2d->convex_body);

		 switch(body2d->components.movement_type) {
		 	case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_ConvexBody2D_Dynamic;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	break;
		 	case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:
		 	break;
		 	default:
		 	 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid movement type.");
		 	break;
		 }

		break;
		default:
		 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid body type.");
		break;
	}
}



/*********************************************
 *
 *               INIT FUNCTIONS
 *
 *********************************************/

static void CVE_Init_RectBody2D(CVE_RectBody2D* self) {
 /*
  calculate area and mass
 */ 
 if(self->components.movement_type == CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC) {
  self->components.area = self->shape_size.x * self->shape_size.y;
  self->components.mass = self->components.area * self->components.density;
  self->components.inv_mass = 1.0 / self->components.mass;
  self->components.rotational_inertia = (1.0 / 12.0) * self->components.mass * (self->shape_size.x * self->shape_size.x + self->shape_size.y * self->shape_size.y);
  self->components.inv_rotational_inertia = 1.0 / self->components.rotational_inertia;
 } else {
  self->components.area = 0;
  self->components.mass = 0;
  self->components.inv_mass = 0;
  self->components.rotational_inertia = 0;
  self->components.inv_rotational_inertia = 0;
 }
 
 /* 
  • calculate centroid
  • calculate vertices, 
  • transformation
  • calculate normals
  • calculate aabb
 */

 
 CVE_Float half_width = self->shape_size.x * 0.5;
 CVE_Float half_height = self->shape_size.y * 0.5;

 self->transformed_vertices[0].x = -half_width;
 self->transformed_vertices[0].y = half_height;

 self->transformed_vertices[1].x = half_width;
 self->transformed_vertices[1].y = half_height;
 
 self->transformed_vertices[2].x = half_width;
 self->transformed_vertices[2].y = -half_height;

 self->transformed_vertices[3].x = -half_width;
 self->transformed_vertices[3].y = -half_height;

 self->components.centroid = self->components.position;
 
 CVE_Vec2f aa, bb;
 CVE_Float s, c;
 CVE_SinCos(self->components.rotation, s, c);
 
 aa.x = c;
 aa.y = s;
 bb.x = -s;
 bb.y = c;
 for(CVE_Uint i = 0; i < 4; i++) {
 	CVE_Vec2f xx, yy, tmp;
 	xx.x = self->transformed_vertices[i].x;
 	xx.y = self->transformed_vertices[i].x;

 	yy.x = self->transformed_vertices[i].y;
 	yy.y = self->transformed_vertices[i].y;

  CVE_Mul2f(tmp, yy, bb);
  CVE_Fma2f(self->transformed_vertices[i], xx, aa, tmp);

 	CVE_Add2f(self->transformed_vertices[i], self->transformed_vertices[i], self->components.position);

  CVE_Min2f(self->components.aabb[0], self->components.aabb[0], self->transformed_vertices[i]);
  CVE_Max2f(self->components.aabb[1], self->components.aabb[1], self->transformed_vertices[i]);
 }
 
 for(CVE_Uint i = 0; i < 4; i++) {
  CVE_Vec2f p1 = self->transformed_vertices[i];
  CVE_Vec2f p2 = self->transformed_vertices[(i+1)%4];
  
  CVE_Vec2f edge, perp;
   CVE_Sub2f(edge, p2, p1);
  
  perp.x = -edge.y;
  perp.y = edge.x;
  CVE_Normalize2f(self->normals[i], perp);
 }
}


static void CVE_Init_CircleBody2D(CVE_CircleBody2D* self) {
 /*
  calculate area and mass
 */ 
 if(self->components.movement_type == CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC) {
  self->components.area = self->radius * self->radius * CVE_PI_FLOAT;
  self->components.mass = self->components.area * self->components.density;
  self->components.inv_mass = 1.0 / self->components.mass;
  self->components.rotational_inertia = (1.0 / 2.0) * self->components.mass * (self->radius * self->radius);   
  self->components.inv_rotational_inertia = 1.0 / self->components.rotational_inertia;
 } else {
  self->components.area = 0;
  self->components.mass = 0;
  self->components.inv_mass = 0;
  self->components.rotational_inertia = 0;
  self->components.inv_rotational_inertia = 0;
 }
 
 self->components.centroid = self->components.position;
 
 CVE_Vec2f vec_radius, pos_a, pos_b;
 CVE_ScalarToVector2f(vec_radius, self->radius);
 CVE_Add2f(pos_a, vec_radius, self->components.position);
 CVE_Sub2f(pos_b, vec_radius, self->components.position);

 
 CVE_Min2f(self->components.aabb[0], pos_a, pos_b);
 CVE_Max2f(self->components.aabb[1], pos_a, pos_b);
}


static void CVE_Init_TriangleBody2D(CVE_TriangleBody2D* triangle_body) {
	
}


static void CVE_Init_ConvexBody2D(CVE_ConvexBody2D* convex_body) {
	
}



/*********************************************
 *
 *               UPDATE FUNCTIONS
 *
 *********************************************/


static void CVE_Update_Nothing(void* self, CVE_Float time) {
	/* do nothing */
}



static void CVE_Update_RectBody2D_Dynamic(CVE_RectBody2D* self, CVE_Float time) {

 CVE_Vec2f time_vec;
 
 CVE_ScalarToVector2f(time_vec, time);
 
 /* force and torque */ 
 CVE_Fma2f(self->components.velocity, self->components.force, time_vec, self->components.velocity);
 CVE_Fma(self->components.omega, self->components.torque, time, self->components.omega);

 CVE_Fma2f(self->components.position, self->components.velocity, time_vec, self->components.position);
 CVE_Fma(self->components.rotation, self->components.omega, time, self->components.rotation);

 CVE_ScalarToVector2f(self->components.force, 0);
 self->components.torque = 0;

 
/*
 calculate vertices
*/
 
 CVE_Float half_width = self->shape_size.x * 0.5;
 CVE_Float half_height = self->shape_size.y * 0.5;

 self->transformed_vertices[0].x = -half_width;
 self->transformed_vertices[0].y = half_height;

 self->transformed_vertices[1].x = half_width;
 self->transformed_vertices[1].y = half_height;
 
 self->transformed_vertices[2].x = half_width;
 self->transformed_vertices[2].y = -half_height;

 self->transformed_vertices[3].x = -half_width;
 self->transformed_vertices[3].y = -half_height;

 self->components.centroid = self->components.position;
 
 CVE_Vec2f aa, bb;
 CVE_Float s, c;
 CVE_SinCos(self->components.rotation, s, c);
 
 aa.x = -c;
 aa.y = s;
 bb.x = s;
 bb.y = c;
 for(CVE_Uint i = 0; i < 4; i++) {
 	CVE_Vec2f xx, yy, tmp;
 	xx.x = self->transformed_vertices[i].x;
 	xx.y = self->transformed_vertices[i].x;

 	yy.x = self->transformed_vertices[i].y;
 	yy.y = self->transformed_vertices[i].y;

  CVE_Mul2f(tmp, yy, bb);
  CVE_Fma2f(self->transformed_vertices[i], xx, aa, tmp);

 	CVE_Add2f(self->transformed_vertices[i], self->transformed_vertices[i], self->components.position);

  CVE_Min2f(self->components.aabb[0], self->components.aabb[0], self->transformed_vertices[i]);
  CVE_Max2f(self->components.aabb[1], self->components.aabb[1], self->transformed_vertices[i]);
 }
 
 for(CVE_Uint i = 0; i < 4; i++) {
  CVE_Vec2f p1 = self->transformed_vertices[i];
  CVE_Vec2f p2 = self->transformed_vertices[(i+1)%4];
  
  CVE_Vec2f edge, perp;
   CVE_Sub2f(edge, p2, p1);
  
  perp.x = -edge.y;
  perp.y = edge.x;
  CVE_Normalize2f(self->normals[i], perp);
 }
}


static void CVE_Update_CircleBody2D_Dynamic(CVE_CircleBody2D* self, CVE_Float time) {
 CVE_Vec2f time_vec; 
 CVE_ScalarToVector2f(time_vec, time);
 
 /* force and torque */ 
 CVE_Fma2f(self->components.velocity, self->components.force, time_vec, self->components.velocity);
 CVE_Fma(self->components.omega, self->components.torque, time, self->components.omega);

 CVE_Fma2f(self->components.position, self->components.velocity, time_vec, self->components.position);
 CVE_Fma(self->components.rotation, self->components.omega, time, self->components.rotation);


 CVE_ScalarToVector2f(self->components.force, 0);
 self->components.torque = 0;

 /*
  recalculate its components
 */
 self->components.centroid = self->components.position;
 
 CVE_Vec2f vec_radius, pos_a, pos_b;
 CVE_ScalarToVector2f(vec_radius, self->radius);
 CVE_Add2f(pos_a, vec_radius, self->components.position);
 CVE_Sub2f(pos_b, vec_radius, self->components.position);

 
 CVE_Min2f(self->components.aabb[0], pos_a, pos_b);
 CVE_Max2f(self->components.aabb[1], pos_a, pos_b);
}


static void CVE_Update_TriangleBody2D_Dynamic(CVE_TriangleBody2D* self, CVE_Float time) {
	
}


static void CVE_Update_ConvexBody2D_Dynamic(CVE_ConvexBody2D* self, CVE_Float time) {
	
}




/*********************************************
 *
 *               PUBLIC FUNCTIONS
 *
 *********************************************/


void cveGetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr) {
	*((CVE_Vec2f*)out_ptr) = ((CVE_Body2D*)body_handle)->components.position;
}


void cveSetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Vec2f *pos = (CVE_Vec2f*)in_ptr;
	((CVE_Body2D*)body_handle)->components.position = *pos;
}

void cveGetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr) {
	*((CVE_Float*)out_ptr) = ((CVE_Body2D*)body_handle)->components.rotation;
}


void cveSetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Float *rot = (CVE_Float*)in_ptr;
	((CVE_Body2D*)body_handle)->components.rotation = *rot;
}


