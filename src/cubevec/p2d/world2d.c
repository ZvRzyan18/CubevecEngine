/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/world2d.h"
#include "cubevec/p2d/collision2d.h"
#include "cubevec/p2d/collision_handle2d.h"
#include <string.h>

extern CVE_Allocator __cve_global_allocator;
extern CVE_ErrorHandler __cve_global_error_handler;


/*********************************************
 *
 *               WORLD2D INTERFACE
 *
 *********************************************/

static void __cve_bruite_force(void* ptr, CVE_Float dt);



/*
 allocate world2d object
*/
CVE_API void cveCreateWorld2D(CVE_World2D* world) {
	(*world) = __cve_global_allocator.allocate(sizeof(CVE_World2D_Internal));

	if((*world) == NULL)
	 __cve_global_error_handler.error_msg("at function [cveCreateWorld2D()] : allocation failed.");

	memset(*world, 0, sizeof(CVE_World2D_Internal));
	
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)(*world);
	__cve_init_body_pool2d(&world2d->body_pool);
	
	__cve_narrowphase_table_init(&world2d->narrow_phase);
}



/*
 cleanup world2d object
*/
CVE_API void cveDestroyWorld2D(CVE_World2D world) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveDestroyWorld2D()] : null world2d.");
 
 switch(world2d->broadphase_type) {
 	case CVE_BROADPHASE2D_BRUITE_FORCE:
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_X:
   __cve_sweep_and_prune2d_destroy(&world2d->sweep_and_prune);
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_Y:
   __cve_sweep_and_prune2d_destroy(&world2d->sweep_and_prune);
 	break;
 	default:
 	 __cve_global_error_handler.error_msg("at function [cveAddBodyWorld2D()] : invalid broadphase type.");
 	break;
 }

 __cve_destroy_body_pool2d(&world2d->body_pool);
	__cve_global_allocator.deallocate(world);
}



/*
 update simulation
*/
CVE_API void cveUpdateWorld2D(CVE_World2D world, CVE_Float time) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

 CVE_Uint step_count;
 
 time *= world2d->inv_substep;
 step_count = 0;
 while(step_count < world2d->substep) {
  step_count++;

 	/* update position */
 	
 	CVE_Body2D *node;

 	node = world2d->body_begin;
 	while(node != NULL) {
 		node->components.update(node, time, world2d->gravity);
 		node = (CVE_Body2D*)node->components.next;
 	}

 	/* detect collision */
 	world2d->broadphase(world2d, time);

 }
}



/*
 set gravity
*/
CVE_API void cveSetGravityWorld2D(CVE_World2D world, CVE_Float* gravity) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveSetGravityWorld2D()] : null world2d.");
 
 world2d->gravity.x = gravity[0];
 world2d->gravity.y = gravity[1];
}


/*
 set iteration
*/
CVE_API void cveSetSubstepWorld2D(CVE_World2D world, CVE_Uint substep) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

 world2d->substep = substep;
 world2d->inv_substep = 1.0 / (CVE_Float)substep;
}



CVE_API void cveSetBroadphaseTypeWorld2D(CVE_World2D world, CVE_Uint type) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveSetBroadphaseTypeWorld2D()] : null world2d.");
 
 if(world2d->body_size > 0)
 	 __cve_global_error_handler.error_msg("at function [cveSetBroadphaseTypeWorld2D()] : select broadphase first before adding body2d.");

 if(world2d->broadphase_type > 0)
 	 __cve_global_error_handler.error_msg("at function [cveSetBroadphaseTypeWorld2D()] : broadphase could only be selected once.");

 world2d->broadphase_type = type;
 switch(type) {
 	case CVE_BROADPHASE2D_BRUITE_FORCE:
   world2d->broadphase = __cve_bruite_force;
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_X:
 	 world2d->broadphase = __cve_sweep_and_prune2d_broadphase_x;
 	 __cve_sweep_and_prune2d_init(&world2d->sweep_and_prune);
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_Y:
 	 world2d->broadphase = __cve_sweep_and_prune2d_broadphase_y;
 	 __cve_sweep_and_prune2d_init(&world2d->sweep_and_prune);
 	break;
 	default:
 	 __cve_global_error_handler.error_msg("at function [cveSetBroadphaseTypeWorld2D()] : invalid broadphase type.");
 	break;
 }
}



CVE_API void cveAddBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D* handle, CVE_Uint type, CVE_Handle ptr) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;
	
	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveAddBodyWorld2D()] : null world2d.");
	if(ptr == NULL)
	 __cve_global_error_handler.error_msg("at function [cveAddBodyWorld2D()] : null input components.");
	 
	__cve_allocate_to_body_pool2d(&world2d->body_pool, type, handle);

 CVE_Body2D               *body = (CVE_Body2D*)*handle;
 CVE_CreateRectBody2D     *rect_create;
 CVE_CreateCircleBody2D   *circle_create;
 CVE_CreateTriangleBody2D *triangle_create;
 CVE_CreateConvexBody2D   *convex_create;
 
 switch(type) {
 	case CVE_BODY2D_TYPE_RECT:
 	 rect_create = (CVE_CreateRectBody2D*)ptr;
 	 body->rect_body.components.movement_type = rect_create->movement_type;
 	 body->rect_body.components.position.x =    rect_create->pre_translate[0];
 	 body->rect_body.components.position.y =    rect_create->pre_translate[1];
   body->rect_body.components.rotation =      rect_create->pre_rotate;
   body->rect_body.components.density =       rect_create->density;
   body->rect_body.components.restitution =   rect_create->restitution;
   body->rect_body.components.friction =      rect_create->friction;
   body->rect_body.shape_size.x =             rect_create->width * rect_create->pre_scale[0];
   body->rect_body.shape_size.y =             rect_create->height * rect_create->pre_scale[1];
   
   CVE_Log2(body->rect_body.components.logarithmic_linear_damping.x, 1.0 - rect_create->linear_damping[0]);
   CVE_Log2(body->rect_body.components.logarithmic_linear_damping.y, 1.0 - rect_create->linear_damping[1]);
   CVE_Log2(body->rect_body.components.logarithmic_angular_damping, 1.0 - rect_create->angular_damping);
 	break;
 	case CVE_BODY2D_TYPE_CIRCLE:
 	 circle_create = (CVE_CreateCircleBody2D*)ptr;
 	 body->circle_body.components.movement_type = circle_create->movement_type;
 	 body->circle_body.components.position.x =    circle_create->pre_translate[0];
 	 body->circle_body.components.position.y =    circle_create->pre_translate[1];
   body->circle_body.components.rotation =      circle_create->pre_rotate;
   body->circle_body.components.density =       circle_create->density;
   body->circle_body.components.restitution =   circle_create->restitution;
   body->circle_body.components.friction =      circle_create->friction;
   body->circle_body.radius =                   circle_create->radius * circle_create->pre_scale;

   CVE_Log2(body->rect_body.components.logarithmic_linear_damping.x, 1.0 - circle_create->linear_damping[0]);
   CVE_Log2(body->rect_body.components.logarithmic_linear_damping.y, 1.0 - circle_create->linear_damping[1]);
   CVE_Log2(body->rect_body.components.logarithmic_angular_damping, 1.0 - circle_create->angular_damping);
 	break;
 	case CVE_BODY2D_TYPE_TRIANGLE:
 	 triangle_create = (CVE_CreateTriangleBody2D*)ptr;
 	break;
 	case CVE_BODY2D_TYPE_CONVEX:
 	 convex_create = (CVE_CreateConvexBody2D*)ptr;
 	break;
 }
 __cve_init_body2d(body);
 
 /*  arrange it as a link list  */
 if(world2d->body_size == 0) {
 	world2d->body_begin = body; 
 	world2d->body_end = body;
 } else {
 	world2d->body_end->components.next = (CVE_BodyInternalPart2D*)body;
 	body->components.prev = (CVE_BodyInternalPart2D*)world2d->body_end;
 	world2d->body_end = body;
 }
 world2d->body_size++;
 
 /*
  add to broadphase container
 */
 switch(world2d->broadphase_type) {
 	case CVE_BROADPHASE2D_BRUITE_FORCE:
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_X:
   __cve_sweep_and_prune2d_add_body(&world2d->sweep_and_prune, body);
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_Y:
   __cve_sweep_and_prune2d_add_body(&world2d->sweep_and_prune, body);
 	break;
 	default:
 	 __cve_global_error_handler.error_msg("at function [cveAddBodyWorld2D()] : invalid broadphase type.");
 	break;
 }
}



CVE_API void cveRemoveBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D handle) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;
	
	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveRemoveBodyWorld2D()] : null world2d.");

 /*  re arrange the nodes  */
 if(world2d->body_size == 0) {
 	return;
 } else if(world2d->body_size == 1) {
 	world2d->body_begin = NULL;
 	world2d->body_end = NULL;
 } else {
  CVE_Body2D *body = (CVE_Body2D*)handle;

  if(body == world2d->body_begin) {
  	world2d->body_begin = (CVE_Body2D*)body->components.next;
  	world2d->body_begin->components.prev = NULL;
  } else if(body == world2d->body_end) {
  	world2d->body_end = (CVE_Body2D*)world2d->body_end->components.prev;
  	world2d->body_end->components.next = NULL;
  } else {
   CVE_Body2D *prev = (CVE_Body2D*)body->components.prev;
   CVE_Body2D *next = (CVE_Body2D*)body->components.next;
   prev->components.next = (CVE_BodyInternalPart2D*)next;
   next->components.prev = (CVE_BodyInternalPart2D*)prev;
  }
 }
 world2d->body_size--;

 /* deallocate the actual data on pool*/
 __cve_deallocate_to_body_pool2d(&world2d->body_pool, handle);
 
 /*
  remove the body into broadphase container
 */
 switch(world2d->broadphase_type) {
 	case CVE_BROADPHASE2D_BRUITE_FORCE:
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_X:
   __cve_sweep_and_prune2d_remove_body(&world2d->sweep_and_prune, (CVE_Body2D*)handle);
 	break;
 	case CVE_BROADPHASE2D_SWEEP_AND_PRUNE_Y:
   __cve_sweep_and_prune2d_remove_body(&world2d->sweep_and_prune, (CVE_Body2D*)handle);
 	break;
 	default:
 	 __cve_global_error_handler.error_msg("at function [cveAddBodyWorld2D()] : invalid broadphase type.");
 	break;
 }
}



/*
 static function
*/
static void __cve_bruite_force(void* ptr, CVE_Float dt) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)ptr;
	CVE_Body2D *node, *node1;
	node = world2d->body_begin;

 while(node != NULL) {
  node1 = (CVE_Body2D*)node->components.next;
  while(node1 != NULL) {

   CVE_Manifold2D manifold;
    
   CVE_Body2D *aa = node;
   CVE_Body2D *bb = node1;
   	
  	if((aa != bb)) {
    world2d->narrow_phase.functions[aa->components.body_type][bb->components.body_type](aa, bb, &manifold);
    if(manifold.collide) {
     __cve_collision_handle_resolve(&manifold);
     __cve_collision_handle_impulse(&manifold);
   }
 	}
   	
  node1 = (CVE_Body2D*)node1->components.next;
 }
	node = (CVE_Body2D*)node->components.next;
 }
}



