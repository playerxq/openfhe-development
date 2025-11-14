//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef __SERIAL_EXTERN_H__
#define __SERIAL_EXTERN_H__

#include "utils/serial-fwd.h"

// clang-format off
// the preprocessor treats commas in template parameters as macro argument separators.
// example:
// for this type "std::map<std::string, std::vector<lbcrypto::EvalKey<lbcrypto::DCRTPoly>>>"
// i get an error "EXTERN_SERIAL_FOR" passed 2 arguments, but takes just 1".
// so, i have to use variadic macros.
// example:
// use
// #define EXTERN_SERIAL_FOR(...)
//     extern template void ::lbcrypto::Serial::Serialize<__VA_ARGS__>(const __VA_ARGS__&, std::ostream&, const ::lbcrypto::SerType::SERJSON&);
//     extern template void ::lbcrypto::Serial::Deserialize<__VA_ARGS__>(__VA_ARGS__&, std::istream&, const ::lbcrypto::SerType::SERJSON&);
// instead of
// #define EXTERN_SERIAL_FOR(TYPE)
//     extern template void        lbcrypto::Serial::Serialize<TYPE>(const TYPE&, std::ostream&, const ::lbcrypto::SerType::SERJSON&);
//     extern template void        lbcrypto::Serial::Deserialize<TYPE>(TYPE&, std::istream&, const ::lbcrypto::SerType::SERJSON&);

#define EXTERN_SERIAL_FOR(...)                                                                                                                             \
extern template void        lbcrypto::Serial::Serialize<__VA_ARGS__>(const __VA_ARGS__&, std::ostream&, const ::lbcrypto::SerType::SERJSON&);              \
extern template void        lbcrypto::Serial::Deserialize<__VA_ARGS__>(__VA_ARGS__&, std::istream&, const ::lbcrypto::SerType::SERJSON&);                  \
extern template void        lbcrypto::Serial::Serialize<__VA_ARGS__>(const __VA_ARGS__&, std::ostream&, const ::lbcrypto::SerType::SERBINARY&);            \
extern template void        lbcrypto::Serial::Deserialize<__VA_ARGS__>(__VA_ARGS__&, std::istream&, const ::lbcrypto::SerType::SERBINARY&);                \
extern template bool        lbcrypto::Serial::SerializeToFile<__VA_ARGS__>(const std::string&, const __VA_ARGS__&, const ::lbcrypto::SerType::SERJSON&);   \
extern template bool        lbcrypto::Serial::DeserializeFromFile<__VA_ARGS__>(const std::string&, __VA_ARGS__&, const ::lbcrypto::SerType::SERJSON&);     \
extern template bool        lbcrypto::Serial::SerializeToFile<__VA_ARGS__>(const std::string&, const __VA_ARGS__&, const ::lbcrypto::SerType::SERBINARY&); \
extern template bool        lbcrypto::Serial::DeserializeFromFile<__VA_ARGS__>(const std::string&, __VA_ARGS__&, const ::lbcrypto::SerType::SERBINARY&);   \
extern template std::string lbcrypto::Serial::SerializeToString<__VA_ARGS__>(const __VA_ARGS__&);                                                          \
extern template void        lbcrypto::Serial::DeserializeFromString<__VA_ARGS__>(__VA_ARGS__&, const std::string&);

// Version without file/string helpers:
#define EXTERN_SERIAL_MAIN_ONLY(...)                                                                                                     \
extern template void lbcrypto::Serial::Serialize<__VA_ARGS__>(const __VA_ARGS__&, std::ostream&, const ::lbcrypto::SerType::SERJSON&);   \
extern template void lbcrypto::Serial::Deserialize<__VA_ARGS__>(__VA_ARGS__&, std::istream&, const ::lbcrypto::SerType::SERJSON&);       \
extern template void lbcrypto::Serial::Serialize<__VA_ARGS__>(const __VA_ARGS__&, std::ostream&, const ::lbcrypto::SerType::SERBINARY&); \
extern template void lbcrypto::Serial::Deserialize<__VA_ARGS__>(__VA_ARGS__&, std::istream&, const ::lbcrypto::SerType::SERBINARY&);
// clang-format on

#endif // __SERIAL_EXTERN_H__
