/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/sweep_and_prune2d.h"
#include <string.h>


extern CVE_Allocator __cve_global_allocator;
extern CVE_ErrorHandler __cve_global_error_handler;




void __cve_sweep_and_prune2d_init(CVE_SweepAndPrune2D *obj) {
	memset(obj, 0, sizeof(CVE_SweepAndPrune2D));
	obj->max_reserve = 10;
}


void __cve_sweep_and_prune2d_destroy(CVE_SweepAndPrune2D *obj) {

}


void __cve_sweep_and_prune2d_add_body(CVE_SweepAndPrune2D *obj, CVE_Body2D *body) {
	
}


void __cve_sweep_and_prune2d_remove_body(CVE_SweepAndPrune2D *obj, CVE_Body2D *body) {
	
}




/*********************************************
 *
 *               BROADPHASE UPDATE 
 *
 *********************************************/

void __cve_sweep_and_prun2d_broadphase_x(CVE_SweepAndPrune2D *obj) {
}


void __cve_sweep_and_prun2d_broadphase_y(CVE_SweepAndPrune2D *obj) {
}


