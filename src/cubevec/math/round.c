#include "cubevec/math/round.h"


/*
 round to zero
*/
CVE_Float __cve_trunc(CVE_Float a) {
	CVE_Uint sign = a < (CVE_Float)0.0;
	CVE_Float out = (CVE_Float)((CVE_Uint)a);
	return sign ? -out : out;
}


/*
 round towards negative inf
*/
CVE_Float __cve_floor(CVE_Float a) {
	CVE_Uint sign = a < (CVE_Float)0.0;
	CVE_Float out = (CVE_Float)((CVE_Uint)a);
 return sign ? -(out+1.0) : out;
}

/*
 round towards positive inf
*/
CVE_Float __cve_ceil(CVE_Float a) {
	CVE_Uint sign = a < (CVE_Float)0.0;
	CVE_Float out = (CVE_Float)((CVE_Uint)a);
 return sign ? -out : (out+1.0);
}

/*
 round per haf 
*/
CVE_Float __cve_round(CVE_Float a) {
 const CVE_Float magic = (CVE_Float)(1 << 23);
 return (a < (CVE_Float)0.0) ? ((a - magic) + magic) : ((a + magic) - magic);
}




