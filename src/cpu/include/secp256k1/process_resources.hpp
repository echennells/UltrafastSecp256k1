#ifndef SECP256K1_PROCESS_RESOURCES_HPP
#define SECP256K1_PROCESS_RESOURCES_HPP

// Explicit teardown for the library's process-wide lazily-built state.
//
// Two things in this library are built on first use and then kept for the life of the
// process: the fused dual-mul generator tables (the verify hot path's G/H tables, built
// on the first ecdsa_verify that needs them) and the batch-verify worker pool (created on
// the first batch-verify _mt call, holding one std::thread per hardware thread).
//
// Both are deliberate. An immortal table has no static-destruction-order hazard, and the
// pool deliberately has NO automatic destruction because its destructor joins threads: at
// static-destruction time on Windows that runs during DLL unload while the loader lock is
// held, and joining there deadlocks.
//
// What is not deliberate is what that looks like from outside. GitHub issue #430: an
// embedder linking this library under the MSVC debug CRT (Boost.Test enables
// _CRTDBG_LEAK_CHECK_DF) gets 259 blocks / ~1.32 MB reported as live at exit --
// one-time and bounded, but indistinguishable from a real leak in CRT and sanitizer
// output, and forcing downstream suppressions. The pool additionally keeps OS threads
// alive to process exit, which is a stronger commitment than a memory cache.
//
// So the retention stays the default and the teardown is explicit. An embedder that runs
// under a leak check calls release_process_resources() before exit; everyone else changes
// nothing and pays nothing.

namespace secp256k1 {

// Free every process-wide lazily-built table and stop the batch worker pool.
//
// Idempotent, and a no-op if the library was never used. NOT a one-way door: the next
// call into the library rebuilds whatever it needs, so this is safe to call at a quiet
// point and keep running.
//
// PRECONDITION: no other thread may be inside this library. This joins the batch worker
// threads and frees the generator tables; calling it concurrently with a verify is
// undefined behaviour.
//
// Do NOT call it from DllMain, from a static destructor, or from anything else that runs
// while the Windows loader lock is held -- joining threads there deadlocks, which is
// exactly why the pool has no automatic destruction in the first place. Call it from your
// own code, on a thread you control, e.g. at the end of main().
//
// Does not cover the ESP32/STM32 generator table, which is function-local on those
// targets; see the comment in Point::dual_scalar_mul_gen_point's embedded arm.
void release_process_resources() noexcept;

// True while any process-wide table is built or the batch worker pool is running.
//
// Exists so that a caller -- and the regression test -- can assert the release actually
// happened rather than trusting that it did. False before the first use of the library,
// and false again after release_process_resources() returns.
bool process_resources_active() noexcept;

}  // namespace secp256k1

#endif  // SECP256K1_PROCESS_RESOURCES_HPP
