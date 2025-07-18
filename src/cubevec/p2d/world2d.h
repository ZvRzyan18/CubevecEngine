/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_WORLD2D_H
#define CVE_WORLD2D_H

#include "cubevec/core.h"
#include "cubevec/math/math.h"
#include "cubevec/p2d/body_pool2d.h"
#include "cubevec/p2d/sweep_and_prune2d.h"


/*********************************************
 *
 *               INTERNAL WORLD2D 
 *
 *********************************************/

typedef struct {
	CVE_Vec2f   gravity;
	CVE_Uint    iteration;
	CVE_Float   epsilon;
	CVE_Float*  iteration_reciprocal;
	
	CVE_BodyPool2D_Internal body_pool;
	
	CVE_SweepAndPrune2D sweep_and_prune;
	CVE_Uint broadphase_type;
	
	void (*broadphase)(void* world);
	
	CVE_Body2D *body_begin;
	CVE_Body2D *body_end;
	CVE_Size   body_size;
} CVE_World2D_Internal;

#endif

