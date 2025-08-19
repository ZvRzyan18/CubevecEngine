/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_SWEEP_AND_PRUNE2D_H
#define CVE_SWEEP_AND_PRUNE2D_H

#include "cubevec/p2d/body2d.h"

/*********************************************
 *
 *           BROADPHASE SWEEP AND PRUNE 
 *
 *********************************************/

typedef struct {
	CVE_Body2D **body_array;
	CVE_Size   body_size;
	CVE_Size   reserve;
	CVE_Size   max_reserve;
} CVE_SweepAndPrune2D;


void __cve_sweep_and_prune2d_init(CVE_SweepAndPrune2D *obj);
void __cve_sweep_and_prune2d_destroy(CVE_SweepAndPrune2D *obj);

void __cve_sweep_and_prune2d_add_body(CVE_SweepAndPrune2D *obj, CVE_Body2D *body);
void __cve_sweep_and_prune2d_remove_body(CVE_SweepAndPrune2D *obj, CVE_Body2D *body);


void __cve_sweep_and_prune2d_broadphase_x(void *world, CVE_Float dt);
void __cve_sweep_and_prune2d_broadphase_y(void *world, CVE_Float dt);


#endif

