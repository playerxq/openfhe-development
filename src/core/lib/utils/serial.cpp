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
  Serialization utilities
 */
#include "utils/serial-templates-impl.h"
#include "utils/serial-instantiator.h"

#include "math/hal/intnat/ubintnat.h"
#include "math/hal/bigintdyn/ubintdyn.h"
#include "math/hal/bigintdyn/mubintvecdyn.h"
#include "math/matrix.h"
#include "lattice/hal/default/ildcrtparams.h"
#include "lattice/hal/default/ilparams.h"
#include "math/hal/vector.h"
#include "lattice/hal/default/dcrtpoly.h"


INSTANTIATE_SERIAL_FOR(intnat::NativeIntegerT<unsigned long>)
INSTANTIATE_SERIAL_FOR(bigintdyn::ubint<unsigned long>)

INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::ILDCRTParams<bigintdyn::ubint<unsigned long>>>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::ILParamsImpl<bigintdyn::ubint<unsigned long>>>)
INSTANTIATE_SERIAL_FOR(std::shared_ptr<lbcrypto::ILParamsImpl<intnat::NativeIntegerT<unsigned long>>>)

INSTANTIATE_SERIAL_FOR(lbcrypto::PolyImpl<bigintdyn::mubintvec<bigintdyn::ubint<unsigned long>>>)
INSTANTIATE_SERIAL_FOR(lbcrypto::PolyImpl<intnat::NativeVectorT<intnat::NativeIntegerT<unsigned long>>>)

INSTANTIATE_SERIAL_FOR(lbcrypto::DCRTPolyImpl<bigintdyn::mubintvec<bigintdyn::ubint<unsigned long>>>)

INSTANTIATE_SERIAL_FOR(lbcrypto::Matrix<bigintdyn::ubint<unsigned long>>)
INSTANTIATE_SERIAL_FOR(lbcrypto::Matrix<intnat::NativeIntegerT<unsigned long>>)
