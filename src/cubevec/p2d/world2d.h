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
#include "cubevec/p2d/collision2d.h"


/*********************************************
 *
 *               INTERNAL WORLD2D 
 *
 *********************************************/

typedef struct {
	CVE_Float max_time_to_rest; /* per seconds */
	CVE_Vec2f rest_linear_threshold; /* per meter */
	CVE_Float rest_angular_threshold; /* per meter */
	CVE_Float active_linear_threshold; /* per meter */
	CVE_Float active_angular_threshold; /* per meter */
} CVE_World2dComponents;

typedef struct {
	CVE_Vec2f   gravity; /* m/s^2 */
	CVE_Uint    substep;
	CVE_Float   inv_substep; /* 1/substep */
	
	CVE_World2dComponents components;
	
	CVE_BodyPool2D_Internal body_pool;
	
	CVE_SweepAndPrune2D sweep_and_prune;
	CVE_Uint broadphase_type;
	
	CVE_NarrowphaseTable narrow_phase;
	
	void (*broadphase)(void* world, CVE_Float dt);
	
	CVE_Body2D *body_begin;
	CVE_Body2D *body_end;
	CVE_Size   body_size;
} CVE_World2D_Internal;

#endif

