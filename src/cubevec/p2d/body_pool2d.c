/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/body_pool2d.h"
#include <string.h>

extern CVE_Allocator __cve_global_allocator;
extern CVE_ErrorHandler __cve_global_error_handler;


/*********************************************
 *
 *               MEMORY POOL INTERNAL
 *
 *********************************************/

void __cve_init_body_pool2d(CVE_BodyPool2D_Internal* body_pool) {
	memset(body_pool, 0, sizeof(CVE_BodyPool2D_Internal));
	body_pool->max_chunk_element_size = 10;
}



void __cve_push_body_pool2d(CVE_BodyPool2D_Internal* body_pool) {
	if(body_pool->chunk_size == 0) {
		body_pool->root_node = (CVE_BodyPool2D_Chunk*)__cve_global_allocator.allocate(sizeof(CVE_BodyPool2D_Chunk));
	 body_pool->end_node = body_pool->root_node;
	 memset(body_pool->root_node, 0, sizeof(CVE_BodyPool2D_Chunk));
	 
	 body_pool->root_node->body_array = __cve_global_allocator.allocate(sizeof(CVE_Body2D) * body_pool->max_chunk_element_size);
	 
	 if(body_pool->root_node->body_array == NULL) 
	  __cve_global_error_handler.error_msg("at function [__cve_push_body_pool2d()] : allocation failed.");
	  
	 memset(body_pool->root_node->body_array, 0, sizeof(CVE_Body2D) * body_pool->max_chunk_element_size);
	} else {
		CVE_BodyPool2D_Chunk *new_chunk = (CVE_BodyPool2D_Chunk*)__cve_global_allocator.allocate(sizeof(CVE_BodyPool2D_Chunk));
	 
	 if(new_chunk == NULL) 
	  __cve_global_error_handler.error_msg("at function [__cve_push_body_pool2d()] : allocation failed.");

	 memset(new_chunk, 0, sizeof(CVE_BodyPool2D_Chunk));
	
	 new_chunk->body_array = __cve_global_allocator.allocate(sizeof(CVE_Body2D) * body_pool->max_chunk_element_size);
  
	 if(new_chunk->body_array == NULL) 
	  __cve_global_error_handler.error_msg("at function [__cve_push_body_pool2d()] : allocation failed.");

  memset(new_chunk->body_array, 0, sizeof(CVE_Body2D) * body_pool->max_chunk_element_size);
	 body_pool->end_node->next = new_chunk;
	 new_chunk->prev = body_pool->end_node;
	 body_pool->end_node = new_chunk;
	 
	}
	body_pool->chunk_size++;
}




void __cve_pop_body_pool2d(CVE_BodyPool2D_Internal* body_pool) {
	if(body_pool->chunk_size == 0) 
	 return;

 if(body_pool->chunk_size == 1) {
  __cve_global_allocator.deallocate(body_pool->end_node->body_array);
  __cve_global_allocator.deallocate(body_pool->end_node);
  body_pool->chunk_size = 0;
  body_pool->root_node = NULL;
  body_pool->end_node = NULL;
 	return;
 }

	CVE_BodyPool2D_Chunk *end_chunk = body_pool->end_node;
	CVE_BodyPool2D_Chunk *prev_chunk = end_chunk->prev;

 prev_chunk->next = NULL;
 body_pool->end_node = prev_chunk;
 
 __cve_global_allocator.deallocate(end_chunk->body_array);
  
 __cve_global_allocator.deallocate(end_chunk);
 body_pool->chunk_size--;
}



void __cve_allocate_to_body_pool2d(CVE_BodyPool2D_Internal* body_pool, CVE_Uint body_type, CVE_BodyHandle2D *body_handle) {
 if(body_pool->chunk_size == 0) {
 	__cve_push_body_pool2d(body_pool);
 	__cve_allocate_to_body_pool2d(body_pool, body_type, body_handle);
 	return;
 } else {
 	
 		CVE_Size i, j;
 	 CVE_BodyPool2D_Chunk *current_node;
 	 
 	 current_node = body_pool->root_node;

   for(i = 0; i < body_pool->chunk_size; i++) {
 		
 		 /* chunk is full, go to the next one */
 		 if(current_node->body_size == body_pool->max_chunk_element_size)
 		  continue;

   	for(j = 0; j < body_pool->max_chunk_element_size; j++) {
 		  if(current_node->body_array[j].body_type == 0) {
 		  	current_node->body_array[j].body_type = body_type;
 		  	current_node->body_size++;
 		  	(*body_handle) = &current_node->body_array[j];
 		  	return;
 		  }
 		 }
 		 
 	 current_node = current_node->next;
  }
 /*
  all chunks are full, so lets allocate more and 
  repeat the entire process
 */
  __cve_push_body_pool2d(body_pool);
  
 	 current_node = body_pool->end_node;

  	for(j = 0; j < body_pool->max_chunk_element_size; j++) {
 		 if(current_node->body_array[j].body_type == 0) {
 		 	current_node->body_array[j].body_type = body_type;
 		  current_node->body_size++;
 		 	(*body_handle) = &current_node->body_array[j];
 		 	return;
 		 }
   }
  
	 __cve_global_error_handler.error_msg("at function [__cve_allocate_to_body_pool2d()] : unexpected error.");
 }
}



void __cve_deallocate_to_body_pool2d(CVE_BodyPool2D_Internal* body_pool, CVE_BodyHandle2D body_handle) {
	CVE_Size i, j;
 CVE_BodyPool2D_Chunk *current_node;
 	current_node = body_pool->root_node;

 for(i = 0; i < body_pool->chunk_size; i++) {

  for(j = 0; j < body_pool->max_chunk_element_size; j++) {
 	 if((&current_node->body_array[j]) == (body_handle)) {
 	 	memset(body_handle, 0, sizeof(CVE_Body2D));
 	 	if((current_node->body_size == 1) && (current_node == body_pool->end_node)) {
 	 		__cve_pop_body_pool2d(body_pool);
 	 	} else
 		 	current_node->body_size--;
 			return;
 		}
 	}
 }
 __cve_global_error_handler.error_msg("at function [__cve_deallocate_to_body_pool2d()] : invalid pointer value.");
}



void __cve_destroy_body_pool2d(CVE_BodyPool2D_Internal* body_pool) {
	CVE_Size i, j, current_body_size;
 CVE_BodyPool2D_Chunk *current_node, *temp_node;
 
 current_node = body_pool->root_node;

 for(i = 0; i < body_pool->chunk_size; i++) {

 	current_body_size = 0;
 	
 	for(j = 0; j < body_pool->max_chunk_element_size; j++) {
 		switch(current_node->body_array[j].body_type) {
 			case CVE_BODY2D_TYPE_RECT:
 			 current_body_size++;
 			break;
 			case CVE_BODY2D_TYPE_CIRCLE:
 			 current_body_size++;
 			break;
 			case CVE_BODY2D_TYPE_TRIANGLE:
 			 current_body_size++;
 			break;
 			case CVE_BODY2D_TYPE_CONVEX:
 			 if(current_node->body_array[j].convex_body.vertices_size > 0) {
 			 	__cve_global_allocator.deallocate(current_node->body_array[j].convex_body.vertices);
 			 	__cve_global_allocator.deallocate(current_node->body_array[j].convex_body.transformed_vertices);
      __cve_global_allocator.deallocate(current_node->body_array[j].convex_body.normals);
 			 }
 			 current_body_size++;
 			break;
 			case 0:
 			 /* not occupied by any object */
 			break;
 			default:
 			 /* error occured, invalid type */
 			break;
 		}
 	}
 	
 	if(current_body_size != current_node->body_size) {
 		/*
 		 there must be some kind of error
 		 or memory corruption
 		*/
 	 __cve_global_error_handler.error_msg("at function [__cve_destroy_body_pool2d()] : unexpected memory error.");
 	}
 	 	 
  current_node = current_node->next;
 }

 current_node = body_pool->root_node;
 temp_node = NULL;

 while(current_node != NULL) {
  temp_node = current_node;
  current_node = current_node->next;
  __cve_global_allocator.deallocate(temp_node->body_array);
  __cve_global_allocator.deallocate(temp_node);
 }
 
}


/*
void __cve_update_all_body_pool2d(CVE_BodyPool2D_Internal* body_pool, CVE_Float time, CVE_Vec2f gravity) {


	CVE_Size i;
 CVE_BodyPool2D_Chunk *current_node;
 
 current_node = body_pool->root_node;

 while(current_node != NULL) {
 
 	for(i = 0; i < body_pool->max_chunk_element_size; i++) {
   
   if(current_node->body_array[i].body_type != 0) {

    CVE_Body2D *body_ptr = &current_node->body_array[i];
    CVE_Add2f(body_ptr->components.force, body_ptr->components.force, gravity);
    body_ptr->components.update(body_ptr, time);
   }
   
 	}
 	current_node = current_node->next;
 }
 
 
}
*/







