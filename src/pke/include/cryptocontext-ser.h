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

/*
  serialize cryptocontext; include this in any app that needs to serialize them
 */

#ifndef __CRYPTOCONTEXT_SER_H__
#define __CRYPTOCONTEXT_SER_H__

#include "pke-serial-extern.h"
// #include "cryptocontext-fwd.h"  // forward decl of CryptoContextImpl and alias CryptoContext
// #include "utils/sertype.h"

// #include <istream>
// #include <string>

// #if !defined(OPENFHE_ENABLE_SERIALIZATION)
//   #define OPENFHE_ENABLE_SERIALIZATION
// #endif

// namespace lbcrypto {
// namespace Serial {

// // ================================= JSON serialization/deserialization
// /**
//  * Deserialize for a CryptoContext (that is, a shared pointer to a
//  * CryptoContextImpl OpenFHE doesn't want multiple copies of the same crypto
//  * context floating around, and it enforces that here
//  *
//  * @param obj - the target for the deserialization
//  * @param stream - where the serialization is coming from
//  * @param sertype - JSON serialization type
//  */
// template <typename Element>
// void Deserialize(CryptoContext<Element>& obj, std::istream& stream, const SerType::SERJSON&);

// template <typename Element>
// bool DeserializeFromFile(const std::string& filename, CryptoContext<Element>& obj, const SerType::SERJSON&);
// template <typename Element>
// void DeserializeFromString(CryptoContext<Element>& obj, const std::string& json);

// // ================================= BINARY serialization/deserialization
// /**
//  * Deserialize for a CryptoContext (that is, a shared pointer to a
//  * CryptoContextImpl OpenFHE doesn't want multiple copies of the same crypto
//  * context floating around, and it enforces that here
//  *
//  * @param obj - the target for the deserialization
//  * @param stream - where the serialization is coming from
//  * @param sertype - BINARY serialization type
//  */
// template <typename Element>
// void Deserialize(CryptoContext<Element>& obj, std::istream& stream, const SerType::SERBINARY&);

// template <typename Element>
// bool DeserializeFromFile(const std::string& filename, CryptoContext<Element>& obj, const SerType::SERBINARY&);

// }  // namespace Serial
// }  // namespace lbcrypto

#endif // __CRYPTOCONTEXT_SER_H__
