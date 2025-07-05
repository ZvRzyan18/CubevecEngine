/*
 CubeVec Engine Core
 under MIT License.
*/

#ifndef CVE_VECTOR_H
#define CVE_VECTOR_H

#include "cubevec/core.h"

/*********************************************
 *
 *               VECTOR TYPES
 *
 *********************************************/

typedef struct {
 CVE_Float x, y;
} CVE_Vec2f;

typedef struct {
	CVE_Float x, y, z;
} CVE_Vec3f;

typedef struct {
	CVE_Float x, y, z, w;
} CVE_Vec4f;

/*********************************************
 *
 *               UNSIGNED INT VECTOR
 *
 *********************************************/


typedef struct {
 CVE_Uint x, y;
} CVE_Vec2u;

typedef struct {
	CVE_Uint x, y, z;
} CVE_Vec3u;

typedef struct {
	CVE_Uint x, y, z, w;
} CVE_Vec4u;


#endif

