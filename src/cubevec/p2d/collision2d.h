/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_COLLISION2D_H
#define CVE_COLLISION2D_H

#include "cubevec/p2d/body2d.h"

#define CVE_MAX_BODY2D_TYPE 4


typedef struct {
 CVE_Body2D *a, *b;
	CVE_Uint   collide;
	CVE_Float  depth;
	CVE_Vec2f  direction;
	CVE_Vec2f  contact[2];
	CVE_Size   contact_size;
} CVE_Manifold2D;

typedef void (*CVE_CollisionDetect)(CVE_Body2D *a, CVE_Body2D *b, CVE_Manifold2D *manifold);

typedef struct {
	CVE_CollisionDetect functions[CVE_MAX_BODY2D_TYPE+1][CVE_MAX_BODY2D_TYPE+1];
} CVE_NarrowphaseTable;

/*
 lookup table function pointers 
 usage : table->functions[a->components.type-1][b->componemts.type-1](a, b, &manifold);
*/
void __cve_narrowphase_table_init(CVE_NarrowphaseTable *table);


#endif

