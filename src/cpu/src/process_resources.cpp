// ============================================================================
// Explicit teardown for the library's process-wide lazily-built state.
// ============================================================================
// See secp256k1/process_resources.hpp for the contract and GitHub issue #430 for why
// this exists. This translation unit owns nothing: it is the single place that knows the
// full set of per-TU release hooks, so an embedder has one call to make instead of
// tracking which internal caches a given release of the library happens to have.
//
// Adding a new process-wide cache means adding its pair of hooks here. Nothing else in
// the library should register teardown -- specifically not atexit() and not a static
// destructor, both of which reintroduce the loader-lock join deadlock the pool avoids.
// ============================================================================

#include "secp256k1/process_resources.hpp"

#include "secp256k1/detail/batch_pool.hpp"

namespace secp256k1 {

namespace fast {
namespace detail {
// Defined in point.cpp, next to the tables they release.
bool gen_tables_active() noexcept;
void release_gen_tables() noexcept;
}  // namespace detail
}  // namespace fast

void release_process_resources() noexcept {
    // Order matters: stop the workers FIRST. A worker parked in the pool's condition
    // variable is not touching the generator tables, but a worker still draining a job
    // would be, and freeing the tables out from under it would be a use-after-free. The
    // documented precondition is that no thread is inside the library, so this ordering
    // is belt-and-braces rather than a correctness argument -- but it costs nothing and
    // it is the order that stays correct if a caller gets the precondition slightly
    // wrong.
    detail::release_batch_worker_pool();
    fast::detail::release_gen_tables();
}

bool process_resources_active() noexcept {
    return detail::batch_worker_pool_active() || fast::detail::gen_tables_active();
}

}  // namespace secp256k1
