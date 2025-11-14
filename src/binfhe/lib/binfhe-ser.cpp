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

#include "utils/serial-templates-impl.h"
#include "utils/serial-instantiator.h"

#include <cereal/types/polymorphic.hpp>

#include "binfhecontext.h"

CEREAL_REGISTER_TYPE(lbcrypto::LWECryptoParams);
CEREAL_REGISTER_TYPE(lbcrypto::LWECiphertextImpl);
CEREAL_REGISTER_TYPE(lbcrypto::LWEPrivateKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::LWEPublicKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::LWESwitchingKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::RLWECiphertextImpl);
CEREAL_REGISTER_TYPE(lbcrypto::RingGSWCryptoParams);
CEREAL_REGISTER_TYPE(lbcrypto::RingGSWEvalKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::RingGSWACCKeyImpl);
CEREAL_REGISTER_TYPE(lbcrypto::BinFHECryptoParams);
CEREAL_REGISTER_TYPE(lbcrypto::BinFHEContext);

// Explicit instantiations for BinFHE types
INSTANTIATE_SERIAL_FOR(lbcrypto::BinFHEContext)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::BinFHEContext>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::RingGSWACCKeyImpl>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::LWESwitchingKeyImpl>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::LWEPrivateKeyImpl>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::LWEPublicKeyImpl>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::LWECiphertextImpl>)
