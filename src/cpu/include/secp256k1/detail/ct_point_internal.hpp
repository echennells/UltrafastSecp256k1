#ifndef SECP256K1_DETAIL_CT_POINT_INTERNAL_HPP
#define SECP256K1_DETAIL_CT_POINT_INTERNAL_HPP

#include "secp256k1/ct/point.hpp"

namespace secp256k1::ct::detail {

// Internal raw-result entry point. Callers handling secret results must keep
// the Jacobian representation until their constant-time output boundary.
CTJacobianPoint scalar_mul_jacobian(const fast::Point& p,
                                    const fast::Scalar& k) noexcept;

} // namespace secp256k1::ct::detail

#endif // SECP256K1_DETAIL_CT_POINT_INTERNAL_HPP
