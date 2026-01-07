//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef _LWE_KEYSWITCHKEY_H_
#define _LWE_KEYSWITCHKEY_H_

#include "lwe-ciphertext-fwd.h"
#include "lwe-keyswitchkey-fwd.h"
#include "math/math-hal.h"
#include "utils/serializable.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {
/**
 * @brief Class that stores the LWE scheme switching key
 */
class LWESwitchingKeyImpl : public Serializable {
public:
    LWESwitchingKeyImpl() = default;

    LWESwitchingKeyImpl(const std::vector<std::vector<std::vector<NativeVector>>>& keyA,
                        const std::vector<std::vector<std::vector<NativeInteger>>>& keyB)
        : m_keyA(keyA), m_keyB(keyB) {}

    LWESwitchingKeyImpl(std::vector<std::vector<std::vector<NativeVector>>>&& keyA,
                        std::vector<std::vector<std::vector<NativeInteger>>>&& keyB) noexcept
        : m_keyA(std::move(keyA)), m_keyB(std::move(keyB)) {}




    LWESwitchingKeyImpl(std::vector<std::vector<std::vector<NativeVector>>>&& keyA,
                        std::vector<std::vector<std::vector<NativeInteger>>>&& keyB, std::vector<LWECiphertext>&& zeros) noexcept
        : m_keyA(std::move(keyA)), m_keyB(std::move(keyB)), m_zeros(std::move(zeros)) {}
//                        std::vector<std::vector<std::vector<NativeInteger>>>&& keyB, std::vector<LWECiphertext>&& zeros, std::vector<LWECiphertext>&& zerosN) noexcept
//        : m_keyA(std::move(keyA)), m_keyB(std::move(keyB)), m_zeros(std::move(zeros)), m_zerosN(std::move(zerosN)) {}



    LWESwitchingKeyImpl(const LWESwitchingKeyImpl& rhs) : m_keyA(rhs.m_keyA), m_keyB(rhs.m_keyB) {}

    LWESwitchingKeyImpl(LWESwitchingKeyImpl&& rhs) noexcept
        : m_keyA(std::move(rhs.m_keyA)), m_keyB(std::move(rhs.m_keyB)) {}

    LWESwitchingKeyImpl& operator=(const LWESwitchingKeyImpl& rhs) {
        m_keyA = rhs.m_keyA;
        m_keyB = rhs.m_keyB;
        return *this;
    }

    LWESwitchingKeyImpl& operator=(LWESwitchingKeyImpl&& rhs) noexcept {
        m_keyA = std::move(rhs.m_keyA);
        m_keyB = std::move(rhs.m_keyB);
        return *this;
    }

    const std::vector<std::vector<std::vector<NativeVector>>>& GetElementsA() const {
        return m_keyA;
    }

    const std::vector<std::vector<std::vector<NativeInteger>>>& GetElementsB() const {
        return m_keyB;
    }

    void SetElementsA(const std::vector<std::vector<std::vector<NativeVector>>>& keyA) {
        m_keyA = keyA;
    }

    void SetElementsB(const std::vector<std::vector<std::vector<NativeInteger>>>& keyB) {
        m_keyB = keyB;
    }



    void SetZeros(std::vector<LWECiphertext>&& zeros) noexcept {
        m_zeros = std::move(zeros);
    }
    const std::vector<LWECiphertext>& GetZeros() const {
        return m_zeros;
    }
//    void SetZerosN(std::vector<LWECiphertext>&& zerosN) noexcept {
//        m_zerosN = std::move(zerosN);
//    }
//    const std::vector<LWECiphertext>& GetZerosN() const {
//        return m_zerosN;
//    }


    bool operator==(const LWESwitchingKeyImpl& other) const {
        return (m_keyA == other.m_keyA && m_keyB == other.m_keyB);
    }

    bool operator!=(const LWESwitchingKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", m_keyA));
        ar(::cereal::make_nvp("b", m_keyB));
        ar(::cereal::make_nvp("z", m_zeros));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }

        ar(::cereal::make_nvp("a", m_keyA));
        ar(::cereal::make_nvp("b", m_keyB));
        ar(::cereal::make_nvp("z", m_zeros));
    }

    std::string SerializedObjectName() const override {
        return "LWEPrivateKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::vector<std::vector<std::vector<NativeVector>>> m_keyA;
    std::vector<std::vector<std::vector<NativeInteger>>> m_keyB;
    std::vector<LWECiphertext> m_zeros;
//    std::vector<LWECiphertext> m_zerosN;
};

}  // namespace lbcrypto

#endif
