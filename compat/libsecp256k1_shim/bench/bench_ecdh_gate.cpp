#include "secp256k1.h"
#include "secp256k1_ecdh.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <memory>

int main() {
    std::array<std::array<unsigned char, 32>, 32> keys{};
    for (std::size_t i = 0; i < keys.size(); ++i)
        keys[i][31] = static_cast<unsigned char>(i + 1);

    std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> ctx(
        secp256k1_context_create(SECP256K1_CONTEXT_NONE), secp256k1_context_destroy);
    if (!ctx) return 1;

    secp256k1_pubkey pubkey{};
    if (secp256k1_ec_pubkey_create(ctx.get(), &pubkey, keys[0].data()) != 1)
        return 1;

    unsigned char output[32]{};
    volatile unsigned char sink = 0;
    for (std::size_t i = 0; i < 1000; ++i)
        if (secp256k1_ecdh(ctx.get(), output, &pubkey, keys[i % keys.size()].data(), nullptr, nullptr) != 1)
            return 1;

    auto const start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < 20000; ++i) {
        if (secp256k1_ecdh(ctx.get(), output, &pubkey, keys[i % keys.size()].data(), nullptr, nullptr) != 1)
            return 1;
        sink = static_cast<unsigned char>(sink ^ output[0]);
    }
    auto const elapsed = std::chrono::steady_clock::now() - start;
    std::printf("shim ECDH %.2f ns/call, checksum=%u\n",
        std::chrono::duration<double, std::nano>(elapsed).count() / 20000.0,
        static_cast<unsigned>(sink));
    return 0;
}
