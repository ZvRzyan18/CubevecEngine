/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_SPATIAL_PARTITION2D_H
#define CVE_SPATIAL_PARTITION2D_H

#include "cubevec/p2d/body2d.h"


typedef struct {
	CVE_Body2D *a, *b;
} CVE_PairBody2D;

typedef struct CVE_GroupOfPair2D CVE_GroupOfPair2D;
struct CVE_GroupOfPair2D {
	CVE_PairBody2D* pairs;
	CVE_Size        pairs_size;
	CVE_GroupOfPair2D *next;
	CVE_GroupOfPair2D *end;
};

typedef struct {
	CVE_GroupOfPair2D* pair;
	
	
} CVE_SpatialPartition2D;


#endif

