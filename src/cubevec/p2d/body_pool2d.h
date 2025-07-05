/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_BODY_POOL2D_H
#define CVE_BODY_POOL2D_H

#include "cubevec/p2d/body2d.h"

/*********************************************
 *
 *               BODY2D POOL
 *
 *********************************************/

/*
 this is designed to minimize the memory fragmentation 
 by keeping the object in chunk (group of array) memory while
 allowing it to be in a link list
*/
typedef struct CVE_BodyPool2D_Chunk CVE_BodyPool2D_Chunk;
struct CVE_BodyPool2D_Chunk {
	CVE_Body2D*          body_array;
	CVE_Size             body_size;
	CVE_BodyPool2D_Chunk *next;
	CVE_BodyPool2D_Chunk *prev;
};

/*
 stack data structure of pool where each node 
 has allocated chunk of memory
*/
typedef struct {
	CVE_Size             max_chunk_element_size;
	CVE_Size             chunk_size;
	CVE_BodyPool2D_Chunk *root_node, *end_node;
	
} CVE_BodyPool2D_Internal;

/*
 initlize all components to zero
*/
void __cve_init_body_pool2d(CVE_BodyPool2D_Internal* body_pool);

/*
 allocate new chunk of memmory and push its node into back
*/
void __cve_push_body_pool2d(CVE_BodyPool2D_Internal* body_pool);
/*
 deallocate the last chunk of memory and pop the node
*/
void __cve_pop_body_pool2d(CVE_BodyPool2D_Internal* body_pool);
/*
 track the data and create an allocation to a pool
*/
void __cve_allocate_to_body_pool2d(CVE_BodyPool2D_Internal* body_pool, CVE_Uint body_type, CVE_BodyHandle2D* body_handle);

/*
 deallocate to body pool
*/
void __cve_deallocate_to_body_pool2d(CVE_BodyPool2D_Internal* body_pool, CVE_BodyHandle2D body_handle);


/*
 destroy all the object safely
*/
void __cve_destroy_body_pool2d(CVE_BodyPool2D_Internal* body_pool);


/*
 invoke all update functions of bodies
*/
void __cve_update_all_body_pool2d(CVE_BodyPool2D_Internal* body_pool, CVE_Float time, CVE_Vec2f gravity);



#endif

