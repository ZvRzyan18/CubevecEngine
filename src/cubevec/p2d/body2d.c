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

static void CVE_Update_Sleep(CVE_Body2D* self, CVE_Float time, CVE_Vec2f gravity);
static void CVE_Update_Nothing(CVE_Body2D* self, CVE_Float time, CVE_Vec2f gravity);

static void CVE_Update_RectBody2D_Dynamic(CVE_RectBody2D* self, CVE_Float time, CVE_Vec2f gravity);
static void CVE_Update_CircleBody2D_Dynamic(CVE_CircleBody2D* self, CVE_Float time, CVE_Vec2f gravity);
static void CVE_Update_TriangleBody2D_Dynamic(CVE_TriangleBody2D* self, CVE_Float time, CVE_Vec2f gravity);
static void CVE_Update_ConvexBody2D_Dynamic(CVE_ConvexBody2D* self, CVE_Float time, CVE_Vec2f gravity);


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
		 	case CVE_BODY2D_MOVEMENT_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_RectBody2D_Dynamic;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	 body2d->components.is_resting = 1;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_KINEMATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	break;
		 	default:
		 	 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid movement type.");
		 	break;
		 }
		 
		 
		break;
		case CVE_BODY2D_TYPE_CIRCLE:

		 CVE_Init_CircleBody2D(&body2d->circle_body);

		 switch(body2d->components.movement_type) {
		 	case CVE_BODY2D_MOVEMENT_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_CircleBody2D_Dynamic;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	 body2d->components.is_resting = 1;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_KINEMATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	break;
		 	default:
		 	 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid movement type.");
		 	break;
		 }
		 
		break;
		case CVE_BODY2D_TYPE_TRIANGLE:

		 CVE_Init_TriangleBody2D(&body2d->triangle_body);

		 switch(body2d->components.movement_type) {
		 	case CVE_BODY2D_MOVEMENT_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_TriangleBody2D_Dynamic;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	 body2d->components.is_resting = 1;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_KINEMATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	break;
		 	default:
		 	 __cve_global_error_handler.error_msg("at function [__cve_init_body2d()] : invalid movement type.");
		 	break;
		 }

		break;
		case CVE_BODY2D_TYPE_CONVEX:

		 CVE_Init_ConvexBody2D(&body2d->convex_body);

		 switch(body2d->components.movement_type) {
		 	case CVE_BODY2D_MOVEMENT_TYPES_DYNAMIC:
		 	 body2d->components.update = (void*)CVE_Update_ConvexBody2D_Dynamic;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_STATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
		 	 body2d->components.is_resting = 1;
		 	break;
		 	case CVE_BODY2D_MOVEMENT_TYPES_KINEMATIC:
		 	 body2d->components.update = (void*)CVE_Update_Nothing;
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
 if(self->components.movement_type == CVE_BODY2D_MOVEMENT_TYPES_DYNAMIC) {
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
 
 CVE_Uint i;
 for(i = 0; i < 4; i++) {
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
 
 for(i = 0; i < 4; i++) {
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
 if(self->components.movement_type == CVE_BODY2D_MOVEMENT_TYPES_DYNAMIC) {
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

static void CVE_Update_Sleep(CVE_Body2D* self, CVE_Float time, CVE_Vec2f gravity) {
/*
 CVE_Vec2f velocity_damping;
 CVE_Float omega_damping;
 CVE_Exp2(velocity_damping.x, time * self->components.logarithmic_linear_damping.x);
 CVE_Exp2(velocity_damping.y, time * self->components.logarithmic_linear_damping.y);
 CVE_Exp2(omega_damping, time * self->components.logarithmic_angular_damping);

 CVE_Mul2f(self->components.velocity, self->components.velocity, velocity_damping);
 self->components.omega *= omega_damping;
*/
#define SLEEP_ROT_THRESHOLD 1e-3
#define SLEEP_POS_THRESHOLD 1e-3

 if(!self->components.is_resting) {
  self->components.update = (void*)CVE_Update_RectBody2D_Dynamic;  
  CVE_ScalarToVector2f(self->components.velocity, 0);
  self->components.omega = 0;
  self->components.update(self, time, gravity);
  return;
 }
 
 if(
  (fabsf(self->components.velocity.x) > SLEEP_POS_THRESHOLD) || (fabsf(self->components.velocity.y) > SLEEP_POS_THRESHOLD) || (fabsf(self->components.omega) > SLEEP_ROT_THRESHOLD)
  || (fabsf(self->components.force.x) > SLEEP_POS_THRESHOLD) || (fabsf(self->components.force.y) > SLEEP_POS_THRESHOLD) || (fabsf(self->components.torque) > SLEEP_ROT_THRESHOLD)
  || (!self->components.is_resting)) {
  self->components.update = (void*)CVE_Update_RectBody2D_Dynamic;
  self->components.is_resting = 0;
  
  CVE_ScalarToVector2f(self->components.velocity, 0);
  self->components.omega = 0;
  self->components.update(self, time, gravity);
  return;
 } 

 CVE_Vec2f time_vec;
 
 CVE_ScalarToVector2f(time_vec, time);
 CVE_Fma2f(self->components.velocity, gravity, time_vec, self->components.velocity);
 
}


static void CVE_Update_Nothing(CVE_Body2D* self, CVE_Float time, CVE_Vec2f gravity) {
	/* do nothing */
	self->components.is_resting = 1;
}



static void CVE_Update_RectBody2D_Dynamic(CVE_RectBody2D* self, CVE_Float time, CVE_Vec2f gravity) {
/*
#define ROT_THRESHOLD 1.2
#define POS_THRESHOLD 1.3

 if(self->components.is_resting) {
  self->components.update = (void*)CVE_Update_Sleep;
  self->components.rest_time = 0.0;
  CVE_ScalarToVector2f(self->components.velocity, 0);
  self->components.omega = 0;
  return;
 }
 
 if(
 ((fabsf(self->components.velocity.x) < POS_THRESHOLD) && (fabsf(self->components.velocity.y) < POS_THRESHOLD) && (fabsf(self->components.omega) < ROT_THRESHOLD))
 ) {
 	self->components.rest_time += time;
 
 	if(self->components.rest_time >= 1.23) {
 	 self->components.update = (void*)CVE_Update_Sleep;
 	 self->components.is_resting = 1;
 	 self->components.rest_time = 0.0;
 	}
 } else
  self->components.rest_time = 0.0;
*/
 CVE_Vec2f time_vec;
 
 CVE_ScalarToVector2f(time_vec, time);
 
 /* force and torque */ 
 CVE_Vec2f linear_acceleration, inv_mass;
 CVE_Float angular_accelertaion;
 
 CVE_ScalarToVector2f(inv_mass, self->components.inv_mass);
 CVE_Fma2f(linear_acceleration, self->components.force, inv_mass, gravity);


 angular_accelertaion = self->components.torque * self->components.inv_rotational_inertia;
 
 CVE_Fma2f(self->components.velocity, linear_acceleration, time_vec, self->components.velocity);
 CVE_Fma(self->components.omega, angular_accelertaion, time, self->components.omega);


 CVE_Vec2f velocity_damping;
 CVE_Float omega_damping;
 CVE_Exp2(velocity_damping.x, time * self->components.logarithmic_linear_damping.x);
 CVE_Exp2(velocity_damping.y, time * self->components.logarithmic_linear_damping.y);
 CVE_Exp2(omega_damping, time * self->components.logarithmic_angular_damping);

 CVE_Mul2f(self->components.velocity, self->components.velocity, velocity_damping);
 self->components.omega *= omega_damping;


 CVE_Fma2f(self->components.position, self->components.velocity, time_vec, self->components.position);
 CVE_Fma(self->components.rotation, self->components.omega, time, self->components.rotation);

 CVE_ScalarToVector2f(self->components.force, 0);
 self->components.torque = 0;

 CVE_WrapAngle(self->components.rotation, self->components.rotation); 

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
 
 CVE_Uint i;
 for(i = 0; i < 4; i++) {
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
 
 for(i = 0; i < 4; i++) {
  CVE_Vec2f p1 = self->transformed_vertices[i];
  CVE_Vec2f p2 = self->transformed_vertices[(i+1)%4];
  
  CVE_Vec2f edge, perp;
   CVE_Sub2f(edge, p2, p1);
  
  perp.x = -edge.y;
  perp.y = edge.x;
  CVE_Normalize2f(self->normals[i], perp);
 }
}


static void CVE_Update_CircleBody2D_Dynamic(CVE_CircleBody2D* self, CVE_Float time, CVE_Vec2f gravity) {

 CVE_Vec2f velocity_damping;
 CVE_Float omega_damping;
 CVE_Exp2(velocity_damping.x, time * self->components.logarithmic_linear_damping.x);
 CVE_Exp2(velocity_damping.y, time * self->components.logarithmic_linear_damping.y);
 CVE_Exp2(omega_damping, time * self->components.logarithmic_angular_damping);

 CVE_Mul2f(self->components.velocity, self->components.velocity, velocity_damping);
 self->components.omega *= omega_damping;


 CVE_Vec2f time_vec;
 
 CVE_ScalarToVector2f(time_vec, time);
 
 /* force and torque */ 
 CVE_Vec2f linear_acceleration, inv_mass;
 CVE_Float angular_accelertaion;
 
 CVE_ScalarToVector2f(inv_mass, self->components.inv_mass);
 CVE_Fma2f(linear_acceleration, self->components.force, inv_mass, gravity);
 
 angular_accelertaion = self->components.torque * self->components.inv_rotational_inertia;
 
 CVE_Fma2f(self->components.velocity, linear_acceleration, time_vec, self->components.velocity);
 CVE_Fma(self->components.omega, angular_accelertaion, time, self->components.omega);

 CVE_Fma2f(self->components.position, self->components.velocity, time_vec, self->components.position);
 CVE_Fma(self->components.rotation, self->components.omega, time, self->components.rotation);

 CVE_ScalarToVector2f(self->components.force, 0);
 self->components.torque = 0;

 CVE_WrapAngle(self->components.rotation, self->components.rotation); 

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


static void CVE_Update_TriangleBody2D_Dynamic(CVE_TriangleBody2D* self, CVE_Float time, CVE_Vec2f gravity) {
	
}


static void CVE_Update_ConvexBody2D_Dynamic(CVE_ConvexBody2D* self, CVE_Float time, CVE_Vec2f gravity) {
	
}




/*********************************************
 *
 *               PUBLIC FUNCTIONS
 *
 *********************************************/


CVE_API void cveGetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr) {
	*((CVE_Vec2f*)out_ptr) = ((CVE_Body2D*)body_handle)->components.position;
}


CVE_API void cveSetPositionBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Vec2f *pos = (CVE_Vec2f*)in_ptr;
	((CVE_Body2D*)body_handle)->components.position = *pos;
}

CVE_API void cveGetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle out_ptr) {
	*((CVE_Float*)out_ptr) = ((CVE_Body2D*)body_handle)->components.rotation;
}


CVE_API void cveSetRotationBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Float *rot = (CVE_Float*)in_ptr;
	((CVE_Body2D*)body_handle)->components.rotation = *rot;
}




CVE_API void cveAddForceBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Body2D* body = ((CVE_Body2D*)body_handle);
	CVE_Add2f(body->components.force, body->components.force, (*(CVE_Vec2f*)in_ptr));
}


CVE_API void cveAddTorqueBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Body2D* body = ((CVE_Body2D*)body_handle);
	body->components.torque += *(CVE_Float*)in_ptr;
}


CVE_API void cveAddLinearImpulseBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Body2D* body = ((CVE_Body2D*)body_handle);
	CVE_Vec2f vec_mass;
	CVE_ScalarToVector2f(vec_mass, body->components.inv_mass);
	CVE_Fma2f(body->components.velocity, (*(CVE_Vec2f*)in_ptr), vec_mass, body->components.velocity);
}


CVE_API void cveAddRotationalImpulseBody2D(CVE_BodyHandle2D body_handle, CVE_Handle in_ptr) {
	CVE_Body2D* body = ((CVE_Body2D*)body_handle);
	body->components.omega += (*(CVE_Float*)in_ptr) * body->components.inv_rotational_inertia;
}



