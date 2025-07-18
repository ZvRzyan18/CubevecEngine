/*
 CubeVec Engine Core
 under MIT License.
*/

#include "cubevec/p2d/collision_handle2d.h"


extern CVE_ErrorHandler __cve_global_error_handler;


void __cve_collision_handle_resolve(CVE_Manifold2D *manifold) {
	CVE_Vec2f move_depth, half;

	CVE_ScalarToVector2f(move_depth, manifold->depth);
	switch(manifold->a->components.movement_type) {
		case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:

 	switch(manifold->b->components.movement_type) {
	 	case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:
	 	 CVE_ScalarToVector2f(half, 0.5);
	 	 CVE_Mul2f(move_depth, move_depth, manifold->direction);
	 	 CVE_Mul2f(move_depth, move_depth, half);
	 	 
	 	 CVE_Sub2f(manifold->a->components.position, manifold->a->components.position, move_depth);
	 	 CVE_Add2f(manifold->b->components.position, manifold->b->components.position, move_depth);

	 	break;
	 	case CVE_BODY_MOVEMENT2D_TYPES_STATIC:
    
	 	 CVE_Mul2f(move_depth, move_depth, manifold->direction);
	 	 CVE_Sub2f(manifold->a->components.position, manifold->a->components.position, move_depth);

	 	break;
	 	case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:

	 	 CVE_Mul2f(move_depth, move_depth, manifold->direction);
	 	 CVE_Sub2f(manifold->a->components.position, manifold->a->components.position, move_depth);

	 	break;
	 	default:
  	 __cve_global_error_handler.error_msg("at function [__cve_collision_handle_resolve()] : B invalid memory error.");
	 	break;
 	}


		break;
		case CVE_BODY_MOVEMENT2D_TYPES_STATIC:

 	switch(manifold->b->components.movement_type) {
	 	case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:

	 	 CVE_Mul2f(move_depth, move_depth, manifold->direction);
	 	 CVE_Add2f(manifold->b->components.position, manifold->b->components.position, move_depth);

	 	break;
	 	case CVE_BODY_MOVEMENT2D_TYPES_STATIC:
	 	 return; /* static, static, */
	 	break;
	 	case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:
	 	 return; /* static, kinematic */
	 	break;
	 	default:
  	 __cve_global_error_handler.error_msg("at function [__cve_collision_handle_resolve()] : B invalid memory error.");
	 	break;
 	}

		break;
		case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:

 	switch(manifold->b->components.movement_type) {
	 	case CVE_BODY_MOVEMENT2D_TYPES_DYNAMIC:

	 	 CVE_Mul2f(move_depth, move_depth, manifold->direction);
	 	 CVE_Add2f(manifold->b->components.position, manifold->b->components.position, move_depth);

	 	break;
	 	case CVE_BODY_MOVEMENT2D_TYPES_STATIC:
	 	 return; /* kinematic, static */
	 	break;
	 	case CVE_BODY_MOVEMENT2D_TYPES_KINEMATIC:
	 	 return; /* kinematic, kinematic */
	 	break;
	 	default:
  	 __cve_global_error_handler.error_msg("at function [__cve_collision_handle_resolve()] : B invalid memory error.");
	 	break;
 	}

		break;
		default:
 	 __cve_global_error_handler.error_msg("at function [__cve_collision_handle_resolve()] : A invalid memory error.");
		break;
	}

}


void __cve_collision_handle_impulse(CVE_Manifold2D *manifold) {
/*
 CVE_Float dp, inv_masses, e, j;

 CVE_Vec2f	relative_velocity, impulse, vec_j, inv_mass, apply_impulse;
 CVE_Uint i;
 for(i = 0; i < manifold->contact_size; i++) {
 CVE_Sub2f(relative_velocity, manifold->b->components.velocity, manifold->a->components.velocity);
 CVE_Dot2f(dp, relative_velocity, manifold->direction);
 
 if(dp > 0.0)
  return;
 
 inv_masses = (manifold->a->components.inv_mass + manifold->b->components.inv_mass);
 CVE_Min(e, manifold->a->components.restitution, manifold->b->components.restitution);
 j = (-(1.0 + e) * dp) / inv_masses;
	j /= (CVE_Float)manifold->contact_size;
	CVE_ScalarToVector2f(vec_j, j);
 CVE_Mul2f(impulse, vec_j, manifold->direction);
 
 
 CVE_ScalarToVector2f(inv_mass, manifold->a->components.inv_mass);
	CVE_Mul2f(apply_impulse, impulse, inv_mass);
	CVE_Sub2f(manifold->a->components.velocity, manifold->a->components.velocity, apply_impulse);
	
 CVE_ScalarToVector2f(inv_mass, manifold->b->components.inv_mass);
	CVE_Mul2f(apply_impulse, impulse, inv_mass);
	CVE_Add2f(manifold->b->components.velocity, manifold->b->components.velocity, apply_impulse);
 }
*/

 CVE_Float dp[2], inv_masses, e, j, j_pos,
  ra_perp_dp, rb_perp_dp, impulse_scalar;
  
 CVE_Vec2f	relative_velocity, impulse, vec_j, inv_mass, apply_impulse,
  ra, rb, omega_vec_a, omega_vec_b, ra_perp, rb_perp, angular_velocity_a, angular_velocity_b,
  relative_velocity_a, relative_velocity_b;
  
 CVE_Body2D *a, *b;
 
 a = manifold->a;
 b = manifold->b;
 
 CVE_Float contact_impulse[2];
 
 CVE_Uint i;
 for(i = 0; i < manifold->contact_size; i++) {
 
 	CVE_Sub2f(ra, a->components.centroid, manifold->contact[i]);
  CVE_Sub2f(rb, b->components.centroid, manifold->contact[i]);
 	 ra_perp.x = -ra.y;
 	 ra_perp.y = ra.x;
 	 rb_perp.x = -rb.y;
 	 rb_perp.y = rb.x;
  CVE_ScalarToVector2f(omega_vec_a, a->components.omega);
  CVE_ScalarToVector2f(omega_vec_b, b->components.omega);

  CVE_Mul2f(angular_velocity_a, ra_perp, omega_vec_a);
  CVE_Mul2f(angular_velocity_b, rb_perp, omega_vec_b);
	
  CVE_Add2f(relative_velocity_a, a->components.velocity, angular_velocity_a);
  CVE_Add2f(relative_velocity_b, b->components.velocity, angular_velocity_b);
  
  CVE_Sub2f(relative_velocity, relative_velocity_b, relative_velocity_a);
  
  
  CVE_Dot2f(dp[i], relative_velocity, manifold->direction);
 
  if(dp[i] > 0.0)
   return;
 
  CVE_Dot2f(ra_perp_dp, ra_perp, manifold->direction);
  CVE_Dot2f(rb_perp_dp, rb_perp, manifold->direction);

  inv_masses = (manifold->a->components.inv_mass + manifold->b->components.inv_mass) + 
	  (ra_perp_dp*ra_perp_dp) * a->components.inv_rotational_inertia +
	  (rb_perp_dp*rb_perp_dp) * b->components.inv_rotational_inertia;


  CVE_Min(e, a->components.restitution, b->components.restitution);
  j = (-(1.0 + e) * dp[i]) / inv_masses;
  j /= (CVE_Float)manifold->contact_size;
  
  contact_impulse[i] = j;
  
 	CVE_ScalarToVector2f(vec_j, j);
  CVE_Mul2f(impulse, vec_j, manifold->direction);


  CVE_ScalarToVector2f(inv_mass, a->components.inv_mass);
 	CVE_Mul2f(apply_impulse, impulse, inv_mass);
 	CVE_Sub2f(a->components.velocity, a->components.velocity, apply_impulse);
 
  CVE_ScalarToVector2f(inv_mass, b->components.inv_mass);
 	CVE_Mul2f(apply_impulse, impulse, inv_mass);
	 CVE_Add2f(b->components.velocity, b->components.velocity, apply_impulse);
 
  CVE_Float rot_impulse;
  CVE_Cross2f(impulse_scalar, ra, impulse);
  rot_impulse = impulse_scalar * a->components.inv_rotational_inertia;
  a->components.omega -= rot_impulse;
  
  CVE_Cross2f(impulse_scalar, rb, impulse);
  rot_impulse = impulse_scalar * b->components.inv_rotational_inertia;
  b->components.omega += rot_impulse;
  
 }


/*
 friction
*/

 CVE_Vec2f tangent, dp_vec, normal_dp, friction_vec;
 const CVE_Float friction = (a->components.friction + b->components.friction) * 0.5;

 for(i = 0; i < manifold->contact_size; i++) {

  CVE_ScalarToVector2f(dp_vec, dp[i]);
  CVE_Mul2f(normal_dp, dp_vec, manifold->direction);
  CVE_Sub2f(tangent, relative_velocity, normal_dp);

  CVE_Vec2f epsilon_vec, pos_tangent;
  CVE_Vec2u is_small;
  CVE_Abs2f(pos_tangent, tangent);
  CVE_ScalarToVector2f(epsilon_vec, CVE_EPSILON_FLOAT);
  CVE_LessThan2f(is_small, pos_tangent, epsilon_vec);
  
  if(is_small.x && is_small.y)
   break;
  else 
   CVE_Normalize2f(tangent, tangent);
 
  CVE_Dot2f(ra_perp_dp, ra_perp, manifold->direction);
  CVE_Dot2f(rb_perp_dp, rb_perp, manifold->direction);

  inv_masses = (manifold->a->components.inv_mass + manifold->b->components.inv_mass) + 
	  (ra_perp_dp*ra_perp_dp) * a->components.inv_rotational_inertia +
	  (rb_perp_dp*rb_perp_dp) * b->components.inv_rotational_inertia;

  CVE_Dot2f(j, relative_velocity, tangent);
  j = -j;
  j /= inv_masses;
  j /= (CVE_Float)manifold->contact_size;
 
  CVE_Abs(j_pos, j);

  if(j_pos <= (contact_impulse[i] * friction)) {
   CVE_ScalarToVector2f(vec_j, j);
   CVE_Mul2f(impulse, vec_j, tangent);
  } else {
   CVE_ScalarToVector2f(vec_j, -contact_impulse[i]);
   CVE_Mul2f(impulse, vec_j, tangent);
   CVE_ScalarToVector2f(friction_vec, friction);
   CVE_Mul2f(impulse, impulse, friction_vec);
  }

  CVE_ScalarToVector2f(inv_mass, a->components.inv_mass);
 	CVE_Mul2f(apply_impulse, impulse, inv_mass);
 	CVE_Sub2f(a->components.velocity, a->components.velocity, apply_impulse);
  
  CVE_ScalarToVector2f(inv_mass, b->components.inv_mass);
 	CVE_Mul2f(apply_impulse, impulse, inv_mass);
	 CVE_Add2f(b->components.velocity, b->components.velocity, apply_impulse);
  
  CVE_Float rot_impulse;

  CVE_Cross2f(impulse_scalar, ra, impulse);
  rot_impulse = impulse_scalar * a->components.inv_rotational_inertia;
  a->components.omega -= rot_impulse;
  
  CVE_Cross2f(impulse_scalar, rb, impulse);
  rot_impulse = impulse_scalar * b->components.inv_rotational_inertia;
  b->components.omega += rot_impulse;

 }

}



