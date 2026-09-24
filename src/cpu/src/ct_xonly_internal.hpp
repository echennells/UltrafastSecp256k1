#ifndef SECP256K1_CT_XONLY_INTERNAL_HPP
#define SECP256K1_CT_XONLY_INTERNAL_HPP

#include "secp256k1/ct/point.hpp"

// This declaration is private to the CPU source directory and is not installed.
// ELF visibility prevents shared builds from exporting an unchecked entry point.
#if defined(__GNUC__) || defined(__clang__)
#define SECP256K1_XONLY_HIDDEN __attribute__((visibility("hidden")))
#else
#define SECP256K1_XONLY_HIDDEN
#endif

namespace secp256k1::ct::detail {

// Only call with a decoder-produced fraction whose denominator is nonzero and
// whose x-coordinate has a secp256k1 lift. The scalar remains secret.
SECP256K1_XONLY_HIDDEN fast::FieldElement ecmult_const_xonly_trusted(
    const fast::FieldElement& xn, const fast::FieldElement& xd,
    const fast::Scalar& q) noexcept;

} // namespace secp256k1::ct::detail

#undef SECP256K1_XONLY_HIDDEN

#endif // SECP256K1_CT_XONLY_INTERNAL_HPP
