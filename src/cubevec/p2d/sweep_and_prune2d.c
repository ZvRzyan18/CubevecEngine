/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/sweep_and_prune2d.h"
#include "cubevec/p2d/collision2d.h"
#include "cubevec/p2d/collision_handle2d.h"
#include "cubevec/p2d/world2d.h"
#include <string.h>


extern CVE_Allocator __cve_global_allocator;
extern CVE_ErrorHandler __cve_global_error_handler;




void __cve_sweep_and_prune2d_init(CVE_SweepAndPrune2D *obj) {
	memset(obj, 0, sizeof(CVE_SweepAndPrune2D));
	obj->max_reserve = 5;
}


void __cve_sweep_and_prune2d_destroy(CVE_SweepAndPrune2D *obj) {
 if(obj->body_array != NULL)
  __cve_global_allocator.deallocate(obj->body_array);
}


void __cve_sweep_and_prune2d_add_body(CVE_SweepAndPrune2D *obj, CVE_Body2D *body) {
	if(obj->reserve == 0) {
		CVE_Body2D** body_array = __cve_global_allocator.allocate(sizeof(CVE_Body2D*) * (obj->body_size + obj->max_reserve));
		memcpy(body_array, obj->body_array, sizeof(CVE_Body2D*) * obj->body_size);
	 if(obj->body_array != NULL)
	  __cve_global_allocator.deallocate(obj->body_array);
	 obj->body_array = body_array;

		obj->reserve = obj->max_reserve;
		__cve_sweep_and_prune2d_add_body(obj, body);
	} else {
  obj->body_array[obj->body_size++] = body;
  obj->reserve--;
	}
}


void __cve_sweep_and_prune2d_remove_body(CVE_SweepAndPrune2D *obj, CVE_Body2D *body) {
	CVE_Uint i;
	
	for(i = 0; i < obj->body_size; i++) 
	 if(obj->body_array[i] == body)
	  break;

 if((obj->reserve+1) > obj->max_reserve) {
		CVE_Body2D** body_array = __cve_global_allocator.allocate(sizeof(CVE_Body2D*) * (obj->body_size-1));
		memcpy(body_array, obj->body_array, sizeof(CVE_Body2D*) * i);
	 memcpy(&body_array[i], &obj->body_array[i + 1], (obj->body_size - i - 1) * sizeof(CVE_Body2D*));

	 if(obj->body_array != NULL)
	  __cve_global_allocator.deallocate(obj->body_array);

  obj->body_array = body_array;
  obj->body_size--;
 } else {
  memcpy(&obj->body_array[i], &obj->body_array[i + 1], (obj->body_size - i - 1) * sizeof(CVE_Body2D*));
  obj->body_size--;
  obj->reserve++;
 }
}




/*********************************************
 *
 *               BROADPHASE UPDATE 
 *
 *********************************************/


void __cve_sweep_and_prune2d_broadphase_x(void *world) {
	CVE_World2D_Internal *world2d = (CVE_World2D_Internal*)world;
 CVE_SweepAndPrune2D *obj = &world2d->sweep_and_prune;
 
 
 /*
  insertion sort for x axis
 */
 CVE_Int i, j;
 CVE_Size n;
 i = 1;
 
 n = obj->body_size;
 CVE_Body2D const** arr = (CVE_Body2D const**)obj->body_array;

 while(i < n) {
  CVE_Body2D const* key = arr[i];
  j = i - 1;
  while (j >= 0 && (arr[j]->components.position.x < key->components.position.x)) {
   arr[j + 1] = arr[j];
   j--;
  }
  arr[j + 1] = key;
  i++;
 }
  
 /*
  broadphase
 */
 for(i = 0; i < obj->body_size; i++) {
 	for(j = i + 1; j < obj->body_size; j++) {
 			
 		CVE_Body2D* a = obj->body_array[i];
 		CVE_Body2D* b = obj->body_array[j];
 			
 		if(a->components.aabb[1].x < b->components.aabb[0].x)
 		 break;
 		
 	
   if(
    a->components.aabb[0].y <= b->components.aabb[1].y 
 || a->components.aabb[1].y >= b->components.aabb[0].y
 		) {

   CVE_Manifold2D manifold;
  
   	if(a != b) {
   	 
     __cve_collide2d(a, b, &manifold);
     if(manifold.collide) {
      __cve_collision_handle_resolve(&manifold);
      __cve_collision_handle_impulse(&manifold);
     }
   	}

 		} /* aabb check */
 		
 		
 	}
 }
}


void __cve_sweep_and_prune2d_broadphase_y(void *world) {
	CVE_World2D_Internal *world2d = (CVE_World2D_Internal*)world;
 CVE_SweepAndPrune2D *obj = &world2d->sweep_and_prune;
 
 
 /*
  insertion sort for y axis
 */
 CVE_Int i, j;
 CVE_Size n;
 i = 1;
 
 n = obj->body_size;
 CVE_Body2D const** arr = (CVE_Body2D const**)obj->body_array;

 while(i < n) {
  CVE_Body2D const* key = arr[i];
  j = i - 1;
  while (j >= 0 && (arr[j]->components.position.y < key->components.position.y)) {
   arr[j + 1] = arr[j];
   j--;
  }
  arr[j + 1] = key;
  i++;
 }
 
 /*
  broadphase
 */
 for(i = 0; i < obj->body_size; i++) {
 	for(j = i + 1; j < obj->body_size; j++) {
 			
 		CVE_Body2D* a = obj->body_array[i];
 		CVE_Body2D* b = obj->body_array[j];
 			
 		if(a->components.aabb[1].y < b->components.aabb[0].y)
 		 break;
 		
 	
   if(
    a->components.aabb[0].x <= b->components.aabb[1].x 
 || a->components.aabb[1].x >= b->components.aabb[0].x
 		) {

   CVE_Manifold2D manifold;
  
   	if(a != b) {
   	 
     __cve_collide2d(a, b, &manifold);
     if(manifold.collide) {
      __cve_collision_handle_resolve(&manifold);
      __cve_collision_handle_impulse(&manifold);
     }
   	}

 		} /* aabb check */
 		
 		
 	}
 }
}


