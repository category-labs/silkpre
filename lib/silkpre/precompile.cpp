/*
   Copyright 2022 The Silkpre Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "precompile.h"

#include <gmp.h>

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

#include <intx/intx.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>

#include <silkpre/blake2b.h>
#include <silkpre/ecdsa.h>
#include <silkpre/rmd160.h>
#include <silkpre/secp256k1n.hpp>
#include <silkpre/sha256.h>
#include <../third_party/bn_wrapper/bn_wrapper.h>

#include <mcl/bn256.hpp>

void f() {
    const mcl::CurveParam& curve = mcl::BN_SNARK1;
    mcl::bn::initPairing(curve);
    // this is just to make sure pairing is working correctly
    const struct TestSet {
	    mcl::CurveParam cp;
	    const char *name;
	    struct G2 {
		    const char *aa;
		    const char *ab;
		    const char *ba;
		    const char *bb;
	    } g2;
	    struct G1 {
		    int a;
		    int b;
	    } g1;
	    const char *e;
    } g_testSetTbl[] = {
	    {
		    mcl::BN_SNARK1,
		    "BN_SNARK1",
		    {
			    "15267802884793550383558706039165621050290089775961208824303765753922461897946",
			    "9034493566019742339402378670461897774509967669562610788113215988055021632533",
			    "644888581738283025171396578091639672120333224302184904896215738366765861164",
			    "20532875081203448695448744255224543661959516361327385779878476709582931298750",
		    },
		    {
			    1, 2
		    },
		    "15163392945550945552839911839294582974434771053565812675833291179413834896953 "
		    "20389211011850518572149982239826345669421868561029856883955740401696801984953 "
		    "17766795911013516700216709333389761327222334145011922123798810516425387779347 "
		    "6064163297423711021549973931984064750876944939004405231004441199168710504090 "
		    "296093106139306574860102680862436174771023602986903675151017278048818344347 "
		    "1573596951222456889652521728261836933382094474023551133585236991207205981715 "
		    "3511871642997169996730611220058787939468653751355351269812083879279936651479 "
		    "17848534184080172844395614793152774197360421729995967636680357250333093768504 "
		    "3273860031361637906105800996652640969711942192883181518057117446820546419132 "
		    "7212721189663231589365009629980400132745687533815732336503876102977912682966 "
		    "18569236611881855981733896549089319395087993987737891870319625215675547032585 "
		    "10088832670068482545658647976676953228519838542958787800193793260459700064172 "
	    }
    };


    const TestSet& ts = g_testSetTbl[0];

	const mcl::bn::G1 P(ts.g1.a, ts.g1.b);
	const mcl::bn::G2 Q(mcl::bn::Fp2(ts.g2.aa, ts.g2.ab), mcl::bn::Fp2(ts.g2.ba, ts.g2.bb));
    mcl::bn::Fp12 e;
    mcl::bn::pairing(e, P, Q);
    //printf(e.getStr(16).c_str());
    
    mcl::bn::Fp12 e2;
    std::stringstream ss(ts.e);
	ss >> e2;
    // printf(e2.getStr(16).c_str());
        // Compare the strings
    // std::string eStr = e.getStr(16);
    // std::string e2Str = e2.getStr(16);

    // if (eStr == e2Str) {
    //     std::cout << "The strings are the same: " << eStr << std::endl;
    // } else {
    //     std::cout << "The strings are different:\n";
    //     std::cout << "e:   " << eStr << "\n";
    //     std::cout << "e2:  " << e2Str << "\n";
    // }


}

enum {
    EVMC_ISTANBUL = 7,
    EVMC_BERLIN = 8,
};

static void right_pad(std::basic_string<uint8_t>& str, const size_t min_size) noexcept {
    if (str.length() < min_size) {
        str.resize(min_size, '\0');
    }
}

uint64_t silkpre_ecrec_gas(const uint8_t*, size_t, int) { return 3'000; }

SilkpreOutput silkpre_ecrec_run(const uint8_t* input, size_t len) {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};

    std::basic_string<uint8_t> d(input, len);
    right_pad(d, 128);

    const auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
    const auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
    const auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

    const bool homestead{false};  // See EIP-2
    if (!silkpre::is_valid_signature(r, s, homestead)) {
        return {out, 0};
    }

    if (v != 27 && v != 28) {
        return {out, 0};
    }

    std::memset(out, 0, 12);
    static secp256k1_context* context{secp256k1_context_create(SILKPRE_SECP256K1_CONTEXT_FLAGS)};
    if (!silkpre_recover_address(out + 12, &d[0], &d[64], v != 27, context)) {
        return {out, 0};
    }
    return {out, 32};
}

uint64_t silkpre_sha256_gas(const uint8_t*, size_t len, int) { return 60 + 12 * ((len + 31) / 32); }

SilkpreOutput silkpre_sha256_run(const uint8_t* input, size_t len) {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};
    silkpre_sha256(out, input, len, /*use_cpu_extensions=*/true);
    return {out, 32};
}

uint64_t silkpre_rip160_gas(const uint8_t*, size_t len, int) { return 600 + 120 * ((len + 31) / 32); }

SilkpreOutput silkpre_rip160_run(const uint8_t* input, size_t len) {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};
    std::memset(out, 0, 12);
    silkpre_rmd160(&out[12], input, len);
    return {out, 32};
}

uint64_t silkpre_id_gas(const uint8_t*, size_t len, int) { return 15 + 3 * ((len + 31) / 32); }

SilkpreOutput silkpre_id_run(const uint8_t* input, size_t len) {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(len))};
    std::memcpy(out, input, len);
    return {out, len};
}

static intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept {
    const intx::uint256 x_squared{x * x};
    if (x <= 64) {
        return x_squared;
    } else if (x <= 1024) {
        return (x_squared >> 2) + 96 * x - 3072;
    } else {
        return (x_squared >> 4) + 480 * x - 199680;
    }
}

static intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept {
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

uint64_t silkpre_expmod_gas(const uint8_t* ptr, size_t len, int rev) {
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : 200u};

    std::basic_string<uint8_t> input(ptr, len);
    right_pad(input, 3 * 32);

    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};

    if (base_len256 == 0 && mod_len256 == 0) {
        return min_gas;
    }

    if (intx::count_significant_words(base_len256) > 1 || intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1) {
        return UINT64_MAX;
    }

    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};

    input.erase(0, 3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.length() > base_len64) {
        input.erase(0, base_len64);
        right_pad(input, 3 * 32);
        if (exp_len64 < 32) {
            input.erase(exp_len64);
            input.insert(0, 32 - exp_len64, '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};

    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32) {
        adjusted_exponent_len = 8 * (exp_len256 - 32);
    }
    if (bit_len > 1) {
        adjusted_exponent_len += bit_len - 1;
    }

    if (adjusted_exponent_len < 1) {
        adjusted_exponent_len = 1;
    }

    const intx::uint256 max_length{std::max(mod_len256, base_len256)};

    intx::uint256 gas;
    if (rev < EVMC_BERLIN) {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    } else {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }

    if (intx::count_significant_words(gas) > 1) {
        return UINT64_MAX;
    } else {
        return std::max(min_gas, static_cast<uint64_t>(gas));
    }
}

SilkpreOutput silkpre_expmod_run(const uint8_t* ptr, size_t len) {
    std::basic_string<uint8_t> input(ptr, len);
    right_pad(input, 3 * 32);

    const uint64_t base_len{intx::be::unsafe::load<uint64_t>(&input[24])};
    input.erase(0, 32);

    const uint64_t exponent_len{intx::be::unsafe::load<uint64_t>(&input[24])};
    input.erase(0, 32);

    const uint64_t modulus_len{intx::be::unsafe::load<uint64_t>(&input[24])};
    input.erase(0, 32);

    if (modulus_len == 0) {
        uint8_t* out{static_cast<uint8_t*>(std::malloc(1))};
        return {out, 0};
    }

    right_pad(input, base_len + exponent_len + modulus_len);

    mpz_t base;
    mpz_init(base);
    if (base_len) {
        mpz_import(base, base_len, 1, 1, 0, 0, input.data());
        input.erase(0, base_len);
    }

    mpz_t exponent;
    mpz_init(exponent);
    if (exponent_len) {
        mpz_import(exponent, exponent_len, 1, 1, 0, 0, input.data());
        input.erase(0, exponent_len);
    }

    mpz_t modulus;
    mpz_init(modulus);
    mpz_import(modulus, modulus_len, 1, 1, 0, 0, input.data());

    uint8_t* out{static_cast<uint8_t*>(std::malloc(modulus_len))};
    std::memset(out, 0, modulus_len);

    if (mpz_sgn(modulus) == 0) {
        mpz_clear(modulus);
        mpz_clear(exponent);
        mpz_clear(base);

        return {out, static_cast<size_t>(modulus_len)};
    }

    mpz_t result;
    mpz_init(result);

    mpz_powm(result, base, exponent, modulus);

    // export as little-endian
    mpz_export(out, nullptr, -1, 1, 0, 0, result);
    // and convert to big-endian
    std::reverse(out, out + modulus_len);

    mpz_clear(result);
    mpz_clear(modulus);
    mpz_clear(exponent);
    mpz_clear(base);

    return {out, static_cast<size_t>(modulus_len)};
}

// Utility functions for zkSNARK related precompiled contracts.
// See Yellow Paper, Appendix E "Precompiled Contracts", as well as
// https://eips.ethereum.org/EIPS/eip-196
// https://eips.ethereum.org/EIPS/eip-197
using Scalar = libff::bigint<libff::alt_bn128_q_limbs>;

// Must be called prior to invoking any other method.
// May be called many times from multiple threads.
static void init_libff() noexcept {
    // magic static
    [[maybe_unused]] static bool initialized = []() noexcept {
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        libff::alt_bn128_pp::init_public_params();
        return true;
    }();
}

static Scalar to_scalar(const uint8_t bytes_be[32]) noexcept {

    mpz_t m;
    mpz_init(m);
    mpz_import(m, 32, /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, bytes_be);
    Scalar out{m};
    mpz_clear(m);
    return out;
}

// Notation warning: Yellow Paper's p is the same libff's q.
// Returns x < p (YP notation).
static bool valid_element_of_fp(const Scalar& x) noexcept {
    return mpn_cmp(x.data, libff::alt_bn128_modulus_q.data, libff::alt_bn128_q_limbs) < 0;
}

mcl::bn::G1 decode_g1_element_mcl(const uint8_t bytes_be[64]) noexcept {
size_t size = 64;
    uint8_t bytes_le[64];
    for (size_t i = 0; i < size; i++) {
    bytes_le[i] = bytes_be[size - 1 - i];
    }

    uint8_t part1[32];
    uint8_t part2[32];

    // Split the 64-byte array into two 32-byte parts
    std::memcpy(part1, bytes_le, 32);
    std::memcpy(part2, bytes_le + 32, 32);

	//mcl::bn::G1 P(le1, le2);
    //printf(P.getStr(16).c_str());
    mcl::bn::Fp a;
    mcl::bn::Fp b;

    bool success1;
    bool success2; 
    // everything is backwards yo
    a.setArray(&success1, part1, 32);
    b.setArray(&success2, part2, 32);

    // if (!(success1 && success2)) {
    //     std::cerr << "Failed to initialize field element from input bytes.\n";
    // } else {
    //     std::cout << "Field element successfully initialized.\n";
    // }

    mcl::bn::G1 P(b,a);
    // End of Dumb code - jk there is not end to it 
    // Need to prin these values and check if multiplcation
    // is working

    return P; 
}

static std::optional<libff::alt_bn128_G1> decode_g1_element(const uint8_t bytes_be[64]) noexcept {
    Scalar x{to_scalar(bytes_be)};
    if (!valid_element_of_fp(x)) {
        return {};
    }

    Scalar y{to_scalar(bytes_be + 32)};
    if (!valid_element_of_fp(y)) {
        return {};
    }

    // // This is dumb code
    // size_t size = 64;
    // uint8_t bytes_le[64];
    // for (size_t i = 0; i < size; i++) {
    // bytes_le[i] = bytes_be[size - 1 - i];
    // }

    // uint8_t part1[32];
    // uint8_t part2[32];

    // // Split the 64-byte array into two 32-byte parts
    // std::memcpy(part1, bytes_le, 32);
    // std::memcpy(part2, bytes_le + 32, 32);

	// //mcl::bn::G1 P(le1, le2);
    // //printf(P.getStr(16).c_str());
    // mcl::bn::Fp a;
    // mcl::bn::Fp b;

    // bool success1;
    // bool success2; 
    // // everything is backwards yo
    // a.setArray(&success1, part1, 32);
    // b.setArray(&success2, part2, 32);

    // if (!(success1 && success2)) {
    //     std::cerr << "Failed to initialize field element from input bytes.\n";
    // } else {
    //     std::cout << "Field element successfully initialized.\n";
    // }

    // mcl::bn::G1 P(b,a);
    // // End of Dumb code - jk there is not end to it 
    // // Need to prin these values and check if multiplcation
    // // is working

    if (x.is_zero() && y.is_zero()) {
        return libff::alt_bn128_G1::zero();
    }

    libff::alt_bn128_G1 point{x, y, libff::alt_bn128_Fq::one()};
    if (!point.is_well_formed()) {
        return {};
    }
    return point;
}

static std::optional<libff::alt_bn128_Fq2> decode_fp2_element(const uint8_t bytes_be[64]) noexcept {
    // big-endian encoding
    Scalar c0{to_scalar(bytes_be + 32)};
    Scalar c1{to_scalar(bytes_be)};

    if (!valid_element_of_fp(c0) || !valid_element_of_fp(c1)) {
        return {};
    }

    return libff::alt_bn128_Fq2{c0, c1};
}

static std::optional<libff::alt_bn128_G2> decode_g2_element(const uint8_t bytes_be[128]) noexcept {
    std::optional<libff::alt_bn128_Fq2> x{decode_fp2_element(bytes_be)};
    if (!x) {
        return {};
    }

    std::optional<libff::alt_bn128_Fq2> y{decode_fp2_element(bytes_be + 64)};
    if (!y) {
        return {};
    }

    if (x->is_zero() && y->is_zero()) {
        return libff::alt_bn128_G2::zero();
    }

    libff::alt_bn128_G2 point{*x, *y, libff::alt_bn128_Fq2::one()};
    if (!point.is_well_formed()) {
        return {};
    }

    if (!(libff::alt_bn128_G2::order() * point).is_zero()) {
        // wrong order, doesn't belong to the subgroup G2
        return {};
    }

    return point;
}

static std::basic_string<uint8_t> encode_g1_element(libff::alt_bn128_G1 p) noexcept {
    std::basic_string<uint8_t> out(64, '\0');
    if (p.is_zero()) {
        return out;
    }

    p.to_affine_coordinates();

    auto x{p.X.as_bigint()};
    auto y{p.Y.as_bigint()};

    // Here we convert little-endian data to big-endian output
    static_assert(sizeof(x.data) == 32);

    std::memcpy(&out[0], y.data, 32);
    std::memcpy(&out[32], x.data, 32);

    std::reverse(out.begin(), out.end());
    return out;
}

uint64_t silkpre_bn_add_gas(const uint8_t*, size_t, int rev) { return rev >= EVMC_ISTANBUL ? 150 : 500; }

SilkpreOutput silkpre_bn_add_impl(std::basic_string<uint8_t> input) {
    init_libff();
    f();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return {nullptr, 0};
    }
    std::optional<libff::alt_bn128_G1> y{decode_g1_element(&input[64])};
    if (!y) {
        return {nullptr, 0};
    }
    mcl::bn::G1 P = decode_g1_element_mcl(input.data());
    mcl::bn::G1 Q = decode_g1_element_mcl(&input[64]);
    mcl::bn::G1 R;
    // MOTHER FUCKER ALL THESE POINTS ARE PROJECTIVE
    mcl::bn::G1::addProj(R, P, Q, true, true);

    std::cout << "SUM MCL: " << R.getStr(mcl::IoEcProj) << std::endl;
    R.normalize();
    std::cout << "SUM Normalized MCL: " << R.getStr(mcl::IoEcProj) << std::endl;
    
    char buf[1024];
    std::cout << "x: ";
    // Mother fucker 
    R.x.getStr(buf, sizeof(buf), 16);
    std::cout << buf << std::endl;

    std::cout << "y: ";
    // Mother fucker
    R.y.getStr(buf, sizeof(buf), 16);
    std::cout << buf << std::endl;


    /// More dumb
    mcl::bn::Fp c, d;
    c = R.x;  // Get the X coordinate
    d = R.y;  // Get the Y coordinate

    uint8_t x_data[32], y_data[32];
    c.serialize(x_data, 32);  // Serialize the X coordinate into a byte array
    d.serialize(y_data, 32);  // Serialize the Y coordinate into a byte array
    std::basic_string<uint8_t> pout(64, '\0');  // Output string of 64 bytes initialized to zero


    // Copy the Y coordinate into the first 32 bytes of the output
    std::memcpy(&pout[0], y_data, 32);
    // Copy the X coordinate into the next 32 bytes of the output
    std::memcpy(&pout[32], x_data, 32);

    // Reverse the byte order to convert to big-endian format
    std::reverse(pout.begin(), pout.end());
    std::cout << "Encoded G1 point (in hex): ";
    for (size_t i = 0; i < pout.size(); ++i) {
        unsigned char byte = pout[i];
        std::cout << (byte < 0x10 ? "0" : "") << std::hex << (int)byte;
    }
    std::cout << std::dec << std::endl;  // Switch back to decimal format for further output if needed



    // why the fuck do the affine coordinates match

    // P_a.normalize();  // Normalize the point to affine coordinates
    // std::string pointStr = P_a.getStr(mcl::IoEcAffine);  // Use IoEcAffine for affine coordinates
    // P_a.normalize();
    //  pointStr = P_a.getStr(mcl::IoEcAffine);  // Use IoEcAffine for affine coordinates

    // std::cout << "P_a: " << pointStr << std::endl;
    // // print point P
    // char buf[1024];
    // P.getStr(buf, sizeof(buf), 16);  // Converts the point to a hex string

    // // Print the result
    // std::cout << "Point P: " << buf << std::endl;

    // // Alternatively, if you want to print the individual coordinates (x, y):
    // std::cout << "x: ";
    // P.x.getStr(buf, sizeof(buf), 16);
    // std::cout << buf << std::endl;

    // std::cout << "y: ";
    // P.y.getStr(buf, sizeof(buf), 16);
    // std::cout << buf << std::endl;
    // // end print point Q


    // mcl::bn::G1 Q = decode_g1_element_mcl(&input[64]);
    // mcl::bn::G1 R;
    // mcl::bn::G1::add(R, P, Q);
    // R.normalize();
    // uint8_t bytes_be[64]; // Array to hold the serialized result
    // size_t size = P.serialize(bytes_be, sizeof(bytes_be));
    // std::cout << "Serialized affine bytes (in BE format) MCL: ";
    // for (size_t i = 0; i < size; ++i) {
    //     printf("%02x", bytes_be[i]);
    // }
    // std::cout << std::endl;

    // Need to serialize into BE array then can just check
    // but should not that 
    //R.

    x->print();  // To print affine coordinates
    x->print_coordinates();  // To print projective coordinates
    
    y->print();  // To print affine coordinates
    y->print_coordinates();  // To print projective coordinates

    libff::alt_bn128_G1 sum{*x + *y};
    sum.print();  // To print affine coordinates
    sum.print_coordinates();  // To print projective coordinates

    const std::basic_string<uint8_t> res{encode_g1_element(sum)};

    uint8_t* out{static_cast<uint8_t*>(std::malloc(res.length()))};
    std::memcpy(out, res.data(), res.length());
    //std::cout << "Serialized affine bytes (in BE format) libff: ";
    // for (size_t i = 0; i < size; ++i) {
    //     printf("%02x", out[i]);
    // }
    // std::cout << std::endl;

    return {out, res.length()};
}

SilkpreOutput bn_add_impl(std::basic_string<uint8_t> input) {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(64))};
    auto retval = add_run(input.data(), out);
    if(retval == 0)
    {
        return {out, 64 };
    }

    std::free(out);
    return {nullptr, 0};
}

static uint32_t use_silkpre =1;

SilkpreOutput silkpre_bn_add_run(const uint8_t* ptr, size_t len) {
    std::basic_string<uint8_t> input(ptr, len);
    right_pad(input, 128);

    if (use_silkpre)
    {
        return silkpre_bn_add_impl(input);
    }
    return bn_add_impl(input);
}

uint64_t silkpre_bn_mul_gas(const uint8_t*, size_t, int rev) { return rev >= EVMC_ISTANBUL ? 6'000 : 40'000; }

SilkpreOutput silkpre_bn_mul_impl(const std::basic_string<uint8_t> input) {
    init_libff();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return {nullptr, 0};
    }

    Scalar n{to_scalar(&input[64])};

    libff::alt_bn128_G1 product{n * *x};
    const std::basic_string<uint8_t> res{encode_g1_element(product)};

    uint8_t* out{static_cast<uint8_t*>(std::malloc(res.length()))};
    std::memcpy(out, res.data(), res.length());
    return {out, res.length()};
}

SilkpreOutput bn_mul_impl(const std::basic_string<uint8_t> input) {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(64))};

    auto retval = mul_run(input.data(), out);
    if (retval == 0)
    {
        return {out, 64};
    }
    std::free(out);
    return {nullptr, 0};
}

SilkpreOutput silkpre_bn_mul_run(const uint8_t* ptr, size_t len) {
    std::basic_string<uint8_t> input(ptr, len); // BAL: eliminate this?
    right_pad(input, 96); // BAL: eliminate this?

    if (use_silkpre)
    {
        return silkpre_bn_mul_impl(input);
    } else {
        return bn_mul_impl(input);
    }
}

static constexpr size_t kSnarkvStride{192};

uint64_t silkpre_snarkv_gas(const uint8_t*, size_t len, int rev) {
    uint64_t k{len / kSnarkvStride};
    return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

SilkpreOutput silkpre_snarkv_impl(const uint8_t* input, size_t len) {
    size_t k{len / kSnarkvStride};

    init_libff();
    using namespace libff;

    static const auto one{alt_bn128_Fq12::one()};
    auto accumulator{one};

    for (size_t i{0}; i < k; ++i) {
        std::optional<alt_bn128_G1> a{decode_g1_element(&input[i * kSnarkvStride])};
        if (!a) {
            return {nullptr, 0};
        }
        std::optional<alt_bn128_G2> b{decode_g2_element(&input[i * kSnarkvStride + 64])};
        if (!b) {
            return {nullptr, 0};
        }

        if (a->is_zero() || b->is_zero()) {
            continue;
        }

        accumulator = accumulator * alt_bn128_miller_loop(alt_bn128_precompute_G1(*a), alt_bn128_precompute_G2(*b));
    }

    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};
    std::memset(out, 0, 32);
    if (alt_bn128_final_exponentiation(accumulator) == one) {
        out[31] = 1;
    }
    return {out, 32};
}

SilkpreOutput bn_snarkv_impl(const uint8_t* input, size_t len) {
    auto retval = batch_snarkv_run(input, len);
    if (retval == 2)
    {
             return {nullptr, 0};
    }
    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};
    std::memset(out, 0, 32);
    out[31] = retval;
    return {out, 32};
}

SilkpreOutput silkpre_snarkv_run(const uint8_t* input, size_t len) {
    if (len % kSnarkvStride != 0) {
        return {nullptr, 0};
    }
    if (use_silkpre)
    {
        return silkpre_snarkv_impl(input, len);
    } else {
        return bn_snarkv_impl(input, len);
    }
}

uint64_t silkpre_blake2_f_gas(const uint8_t* input, size_t len, int) {
    if (len < 4) {
        // blake2_f_run will fail anyway
        return 0;
    }
    return intx::be::unsafe::load<uint32_t>(input);
}

SilkpreOutput silkpre_blake2_f_run(const uint8_t* input, size_t len) {
    if (len != 213) {
        return {nullptr, 0};
    }
    uint8_t f{input[212]};
    if (f != 0 && f != 1) {
        return {nullptr, 0};
    }

    SilkpreBlake2bState state{};
    if (f) {
        state.f[0] = std::numeric_limits<uint64_t>::max();
    }

    static_assert(std::endian::native == std::endian::little);
    static_assert(sizeof(state.h) == 8 * 8);
    std::memcpy(&state.h, input + 4, 8 * 8);

    uint8_t block[SILKPRE_BLAKE2B_BLOCKBYTES];
    std::memcpy(block, input + 68, SILKPRE_BLAKE2B_BLOCKBYTES);

    std::memcpy(&state.t, input + 196, 8 * 2);

    uint32_t r{intx::be::unsafe::load<uint32_t>(input)};
    silkpre_blake2b_compress(&state, block, r);

    uint8_t* out{static_cast<uint8_t*>(std::malloc(64))};
    std::memcpy(&out[0], &state.h[0], 8 * 8);
    return {out, 64};
}

const SilkpreContract kSilkpreContracts[SILKPRE_NUMBER_OF_ISTANBUL_CONTRACTS] = {
    {silkpre_ecrec_gas, silkpre_ecrec_run},       {silkpre_sha256_gas, silkpre_sha256_run},
    {silkpre_rip160_gas, silkpre_rip160_run},     {silkpre_id_gas, silkpre_id_run},
    {silkpre_expmod_gas, silkpre_expmod_run},     {silkpre_bn_add_gas, silkpre_bn_add_run},
    {silkpre_bn_mul_gas, silkpre_bn_mul_run},     {silkpre_snarkv_gas, silkpre_snarkv_run},
    {silkpre_blake2_f_gas, silkpre_blake2_f_run},
};
