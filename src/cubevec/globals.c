/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/core.h"
#include <string.h>

/*********************************************
 *
 *               GLOBALS
 *
 *********************************************/


CVE_Allocator    __cve_global_allocator;
CVE_ErrorHandler __cve_global_error_handler;
/*
 make sure that is is a valid pointer or else it will gonna crash
*/

void cveSetGlobalAllocator(CVE_Allocator* allocator) {
	if(allocator == NULL)
	 return;
	memcpy(&__cve_global_allocator, allocator, sizeof(CVE_Allocator));
}


void cveSetGlobalErrorHandler(CVE_ErrorHandler* handler) {
	if(handler == NULL)
	 return;
	memcpy(&__cve_global_error_handler, handler, sizeof(CVE_ErrorHandler));
}


