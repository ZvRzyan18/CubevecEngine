/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/world2d.h"
#include "cubevec/p2d/collision2d.h"
#include <string.h>

extern CVE_Allocator __cve_global_allocator;
extern CVE_ErrorHandler __cve_global_error_handler;


/*********************************************
 *
 *               WORLD2D INTERFACE
 *
 *********************************************/


/*
 allocate world2d object
*/
void cveCreateWorld2D(CVE_World2D* world) {
	(*world) = __cve_global_allocator.allocate(sizeof(CVE_World2D_Internal));

	if((*world) == NULL)
	 __cve_global_error_handler.error_msg("at function [cveCreateWorld2D()] : allocation failed.");

	memset(*world, 0, sizeof(CVE_World2D_Internal));
	
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)(*world);
	__cve_init_body_pool2d(&world2d->body_pool);
}

/*
 cleanup world2d object
*/
void cveDestroyWorld2D(CVE_World2D world) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveDestroyWorld2D()] : null world2d.");
 
 
 if(world2d->iteration > 0)
  __cve_global_allocator.deallocate(world2d->iteration_reciprocal);

 __cve_destroy_body_pool2d(&world2d->body_pool);
	__cve_global_allocator.deallocate(world);
}


/*
 update simulation
*/
void cveUpdateWorld2D(CVE_World2D world, CVE_Float time) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;
 CVE_Uint curr_iteration = 0;
 while(world2d->iteration - curr_iteration) {
 	time *= world2d->iteration_reciprocal[curr_iteration++];
 	
 	/* update position */
 	__cve_update_all_body_pool2d(&world2d->body_pool, time, world2d->gravity);
 	
 	/* detect collision */
	CVE_Size i, j;
 CVE_BodyPool2D_Chunk *current_node, *current_node1;
 
 current_node = world2d->body_pool.root_node;

 while(current_node != NULL) {
 
 	for(i = 0; i < world2d->body_pool.max_chunk_element_size-1; i++) {
   
   if(current_node->body_array[i].body_type != 0) {

    current_node1 = world2d->body_pool.root_node;
    while(current_node1 != NULL) {
    	

    	for(j = i; j < world2d->body_pool.max_chunk_element_size; j++) {
   
      if(current_node->body_array[j].body_type != 0) {
       CVE_Manifold2D manifold;
       __cve_collide2d(&current_node->body_array[i], &current_node->body_array[j], &manifold);
      }
    	}
    	current_node1 = current_node1->next;
    }

   }
   
 	}
 	current_node = current_node->next;
 }




 	
 	/* resolve collision */
 	
 	
 }
}


/*
 set gravity
*/
void cveSetGravityWorld2D(CVE_World2D world, CVE_Float* gravity) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveSetGravityWorld2D()] : null world2d.");
 
 world2d->gravity.x = gravity[0];
 world2d->gravity.y = gravity[1];
}


/*
 set iteration
*/
void cveSetIterationWorld2D(CVE_World2D world, CVE_Uint iteration) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveSetIterationWorld2D()] : null world2d.");

	if(world2d->iteration != 0) {
	 __cve_global_allocator.deallocate(world2d->iteration_reciprocal);
	 world2d->iteration = iteration;
	 world2d->iteration_reciprocal = (CVE_Float*)__cve_global_allocator.allocate(world2d->iteration * sizeof(CVE_Float));

	 if(world2d->iteration_reciprocal == NULL)
	  __cve_global_error_handler.error_msg("at function [cveSetIterationWorld2D()] : allocation failed.");
	 
	 for(CVE_Uint i = 0; i < world2d->iteration; i++)
		 world2d->iteration_reciprocal[i] = 1.0 / (CVE_Float)(i+1);
 } else {
		world2d->iteration = iteration;
		world2d->iteration_reciprocal = (CVE_Float*)__cve_global_allocator.allocate(world2d->iteration * sizeof(CVE_Float));
		
	 if(world2d->iteration_reciprocal == NULL)
	  __cve_global_error_handler.error_msg("at function [cveSetIterationWorld2D()] : allocation failed.");

		for(CVE_Uint i = 0; i < world2d->iteration; i++)
		 world2d->iteration_reciprocal[i] = 1.0 / (CVE_Float)(i+1);
 }
}



void cveSetEpsilonWorld2D(CVE_World2D world, CVE_Float epsilon) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;

	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveSetEpsilonWorld2D()] : null world2d.");

 world2d->epsilon = epsilon;
}



void cveAddBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D* handle, CVE_Uint type, CVE_Handle ptr) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;
	
	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveAddBodyWorld2D()] : null world2d.");
	if(ptr == NULL)
	 __cve_global_error_handler.error_msg("at function [cveAddBodyWorld2D()] : null input components.");
	 
	__cve_allocate_to_body_pool2d(&world2d->body_pool, type, handle);

 CVE_Body2D               *body = (CVE_Body2D*)handle->body_handle;
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
   body->rect_body.shape_size.x =             rect_create->width * rect_create->pre_scale[0];
   body->rect_body.shape_size.y =             rect_create->height * rect_create->pre_scale[1];
 	break;
 	case CVE_BODY2D_TYPE_CIRCLE:
 	 circle_create = (CVE_CreateCircleBody2D*)ptr;
 	break;
 	case CVE_BODY2D_TYPE_TRIANGLE:
 	 triangle_create = (CVE_CreateTriangleBody2D*)ptr;
 	break;
 	case CVE_BODY2D_TYPE_CONVEX:
 	 convex_create = (CVE_CreateConvexBody2D*)ptr;
 	break;
 }
 __cve_init_body2d(body);
}



void cveRemoveBodyWorld2D(CVE_World2D world, CVE_BodyHandle2D handle) {
	CVE_World2D_Internal* world2d = (CVE_World2D_Internal*)world;
	
	if(world2d == NULL)
	 __cve_global_error_handler.error_msg("at function [cveRemoveBodyWorld2D()] : null world2d.");

 __cve_deallocate_to_body_pool2d(&world2d->body_pool, handle);
}


