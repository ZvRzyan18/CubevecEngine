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

static void CVE_Init_RectBody2D(CVE_RectBody2D* rect_body) {
	
}


static void CVE_Init_CircleBody2D(CVE_CircleBody2D* circle_body) {
	
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
	//do nothing
}




static void CVE_Update_RectBody2D_Dynamic(CVE_RectBody2D* self, CVE_Float time) {
 CVE_Vec2f time_vec;
 
 CVE_ScalarToVector2f(time_vec, time);
 
 //force and torque
 CVE_Fma2f(self->components.velocity, self->components.force, time_vec, self->components.velocity);
 CVE_Fma(self->components.omega, self->components.torque, time, self->components.omega);
 
 CVE_Fma2f(self->components.position, self->components.velocity, time_vec, self->components.position);
 CVE_Fma(self->components.rotation, self->components.omega, time, self->components.rotation);


 CVE_ScalarToVector2f(self->components.force, 0);
 self->components.omega = 0;
 

/*
 calculate vertices
*/
 CVE_Float half_width = self->shape_size.x * 0.5;
 CVE_Float half_height = self->shape_size.y * 0.5;

 CVE_Vec4f *transformed = (CVE_Vec4f*)self->transformed_vertices;
 CVE_Vec4f p1, p2, p3, xx, yy, aa, bb, product;
 CVE_Float s, c;
 
 s = sinf(self->components.rotation);
 c = cosf(self->components.rotation);
 
  p1.x = -half_width;
  p1.y = half_height;
  p1.z = half_width;
  p1.w = half_height;

  p2.x = half_width;
  p2.y = -half_height;
  p2.z = -half_width;
  p2.w = -half_height;
  
  p3.x = self->components.position.x;
  p3.y = self->components.position.y;
  p3.z = self->components.position.x;
  p3.w = self->components.position.y;
  
  aa.x = -c;
  aa.y = s;
  aa.z = -c;
  aa.w = s;
  
  bb.x = s;
  bb.y = c;
  bb.z = s;
  bb.w = c;

  xx.x = p1.x;
  xx.y = p1.x;
  xx.z = p1.z;
  xx.w = p1.z;
  
  yy.x = p1.y;
  yy.y = p1.y;
  yy.z = p1.w;
  yy.w = p1.w;
  
  CVE_Mul4f(product, yy, bb);
  CVE_Fma4f(transformed[0], xx, aa, product);


  xx.x = p2.x;
  xx.y = p2.x;
  xx.z = p2.z;
  xx.w = p2.z;
  
  yy.x = p2.y;
  yy.y = p2.y;
  yy.z = p2.w;
  yy.w = p2.w;
  
  CVE_Mul4f(product, yy, bb);
  CVE_Fma4f(transformed[1], xx, aa, product);
  
  CVE_Add4f(transformed[0], transformed[0], p3);
  CVE_Add4f(transformed[1], transformed[1], p3);
  
 self->components.centroid = self->components.position;

 //aabb calculation
 CVE_Min2f(self->components.aabb[0], self->transformed_vertices[0], self->transformed_vertices[1]);
 CVE_Min2f(self->components.aabb[0], self->components.aabb[0], self->transformed_vertices[2]);
 CVE_Min2f(self->components.aabb[0], self->components.aabb[0], self->transformed_vertices[3]);

 CVE_Max2f(self->components.aabb[1], self->transformed_vertices[0], self->transformed_vertices[1]);
 CVE_Max2f(self->components.aabb[1], self->components.aabb[1], self->transformed_vertices[2]);
 CVE_Max2f(self->components.aabb[1], self->components.aabb[1], self->transformed_vertices[3]);


 //normal calculation
 CVE_Vec2f edge, perp;
 
 //normal 0
 CVE_Sub2f(edge, self->transformed_vertices[1], self->transformed_vertices[0]);
 perp.x = -edge.y;
 perp.y = edge.x;
 CVE_Normalize2f(self->normals[0], perp);

 //normal 1
 CVE_Sub2f(edge, self->transformed_vertices[2], self->transformed_vertices[1]);
 perp.x = -edge.y;
 perp.y = edge.x;
 CVE_Normalize2f(self->normals[1], perp);

 //normal 2
 CVE_Sub2f(edge, self->transformed_vertices[3], self->transformed_vertices[2]);
 perp.x = -edge.y;
 perp.y = edge.x;
 CVE_Normalize2f(self->normals[2], perp);

 //normal 3
 CVE_Sub2f(edge, self->transformed_vertices[0], self->transformed_vertices[3]);
 perp.x = -edge.y;
 perp.y = edge.x;
 CVE_Normalize2f(self->normals[3], perp);
}


static void CVE_Update_CircleBody2D_Dynamic(CVE_CircleBody2D* self, CVE_Float time) {
	
}


static void CVE_Update_TriangleBody2D_Dynamic(CVE_TriangleBody2D* self, CVE_Float time) {
	
}


static void CVE_Update_ConvexBody2D_Dynamic(CVE_ConvexBody2D* self, CVE_Float time) {
	
}

