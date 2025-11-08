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

#ifndef __SERIAL_INSTANTIATOR_H__
#define __SERIAL_INSTANTIATOR_H__

#include "utils/serial-fwd.h"

// clang-format off
#define INSTANTIATE_SERIAL_FOR(TYPE)   \
template void        lbcrypto::Serial::Serialize<TYPE>(const TYPE&, std::ostream&, const ::lbcrypto::SerType::SERJSON&);              \
template void        lbcrypto::Serial::Deserialize<TYPE>(TYPE&, std::istream&, const ::lbcrypto::SerType::SERJSON&);                  \
template void        lbcrypto::Serial::Serialize<TYPE>(const TYPE&, std::ostream&, const ::lbcrypto::SerType::SERBINARY&);            \
template void        lbcrypto::Serial::Deserialize<TYPE>(TYPE&, std::istream&, const ::lbcrypto::SerType::SERBINARY&);                \
template bool        lbcrypto::Serial::SerializeToFile<TYPE>(const std::string&, const TYPE&, const ::lbcrypto::SerType::SERJSON&);   \
template bool        lbcrypto::Serial::DeserializeFromFile<TYPE>(const std::string&, TYPE&, const ::lbcrypto::SerType::SERJSON&);     \
template bool        lbcrypto::Serial::SerializeToFile<TYPE>(const std::string&, const TYPE&, const ::lbcrypto::SerType::SERBINARY&); \
template bool        lbcrypto::Serial::DeserializeFromFile<TYPE>(const std::string&, TYPE&, const ::lbcrypto::SerType::SERBINARY&);   \
template std::string lbcrypto::Serial::SerializeToString<TYPE>(const TYPE&);                                                          \
template void        lbcrypto::Serial::DeserializeFromString<TYPE>(TYPE&, const std::string&);

// Version without file/string helpers:
#define INSTANTIATE_SERIAL_MAIN_ONLY(TYPE)                                                                            \
template void   lbcrypto::Serial::Serialize<TYPE>(const TYPE&, std::ostream&, const ::lbcrypto::SerType::SERJSON&);   \
template void   lbcrypto::Serial::Deserialize<TYPE>(TYPE&, std::istream&, const ::lbcrypto::SerType::SERJSON&);       \
template void   lbcrypto::Serial::Serialize<TYPE>(const TYPE&, std::ostream&, const ::lbcrypto::SerType::SERBINARY&); \
template void   lbcrypto::Serial::Deserialize<TYPE>(TYPE&, std::istream&, const ::lbcrypto::SerType::SERBINARY&);
// clang-format on

#endif // __SERIAL_INSTANTIATOR_H__
