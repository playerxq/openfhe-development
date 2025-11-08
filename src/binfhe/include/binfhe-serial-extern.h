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

/*
  Header file adding serialization support to Boolean circuit FHE
 */

#ifndef __BINFHECONTEXT_SERIAL_EXTERN_H__
#define __BINFHECONTEXT_SERIAL_EXTERN_H__

#include "utils/serial-extern.h"
#include <memory>

namespace lbcrypto {
class BinFHEContext;

class LWECryptoParams;
class LWECiphertextImpl;
class LWEPrivateKeyImpl;
class LWEPublicKeyImpl;
class LWESwitchingKeyImpl;

class RLWECiphertextImpl;

class RingGSWCryptoParams;
class RingGSWEvalKeyImpl;
class RingGSWACCKeyImpl;

class BinFHECryptoParams;
} // namespace lbcrypto

EXTERN_SERIAL_FOR(lbcrypto::LWECryptoParams)
EXTERN_SERIAL_FOR(lbcrypto::LWECiphertextImpl)
EXTERN_SERIAL_FOR(lbcrypto::LWEPrivateKeyImpl)
EXTERN_SERIAL_FOR(lbcrypto::LWEPublicKeyImpl)
EXTERN_SERIAL_FOR(lbcrypto::LWESwitchingKeyImpl)
EXTERN_SERIAL_FOR(lbcrypto::RLWECiphertextImpl)
EXTERN_SERIAL_FOR(lbcrypto::RingGSWCryptoParams)
EXTERN_SERIAL_FOR(lbcrypto::RingGSWEvalKeyImpl)
EXTERN_SERIAL_FOR(lbcrypto::RingGSWACCKeyImpl)
EXTERN_SERIAL_FOR(lbcrypto::BinFHECryptoParams)
EXTERN_SERIAL_FOR(lbcrypto::BinFHEContext)

EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::RingGSWACCKeyImpl>)
EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::LWESwitchingKeyImpl>)
EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::LWEPrivateKeyImpl>)
EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::LWEPublicKeyImpl>)
EXTERN_SERIAL_FOR(std::shared_ptr<lbcrypto::LWECiphertextImpl>)

#endif // __BINFHECONTEXT_SERIAL_EXTERN_H__

