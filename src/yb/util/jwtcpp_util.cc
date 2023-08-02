// Copyright (c) YugabyteDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.  You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.  See the License for the specific language governing permissions and limitations
// under the License.

#include "yb/util/jwtcpp_util.h"

#include <jwt-cpp/jwt.h>
#include <glog/logging.h>

#include "yb/gutil/casts.h"

namespace yb::util {

using jwt::decoded_jwt;
using jwt::jwk;
using jwt::jwks;
using jwt::verifier;
using jwt::json::type;
using jwt::traits::kazuho_picojson;

Result<jwks<kazuho_picojson>> ParseJwks(const std::string& key_set) {
  try {
    return jwt::parse_jwks(key_set);
  } catch (const std::exception& e) {
    VLOG(4) << Format("Invalid JWKS: $0, Error: $1", key_set, e.what());
    return STATUS_FORMAT(InvalidArgument, "Invalid JWKS - $0", e.what());
  } catch (...) {
    VLOG(4) << Format("Invalid JWKS: $0", key_set);
    return STATUS(InvalidArgument, "Invalid JWKS.");
  }
}

Result<jwk<kazuho_picojson>> GetJwkFromJwks(
    const jwks<kazuho_picojson>& jwks, const std::string& key_id) {
  try {
    return jwks.get_jwk(key_id);
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Couldn't fetch key with id: $0 from JWKS - $1", key_id, e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Couldn't fetch key with id: $0 from JWKS", key_id);
  }
}

Result<std::string> GetX5cKeyValueFromJWK(const jwk<kazuho_picojson>& jwk) {
  try {
    return jwk.get_x5c_key_value();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching x5c from JWK failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching x5c from JWK failed");
  }
}

Result<std::string> GetKeyType(const jwk<kazuho_picojson>& jwk) {
  try {
    return jwk.get_key_type();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching key type from JWK failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching key type from JWK failed");
  }
}

Result<std::string> GetClaimFromJwkAsString(
    const jwk<kazuho_picojson>& jwk, const std::string& name) {
  try {
    return jwk.get_jwk_claim(name).as_string();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching claim $0 from JWK failed - $1", name, e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Fetching claim $0 from JWK failed", name);
  }
}

Result<std::string> ConvertX5cDerToPem(const std::string& x5c) {
  try {
    return jwt::helper::convert_base64_der_to_pem(x5c);
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Converting JWT x5c to PEM format failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Converting JWT x5c to PEM format failed");
  }
}

Result<decoded_jwt<kazuho_picojson>> DecodeJwt(const std::string& token) {
  try {
    return jwt::decode(token);
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Parsing JWT failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Parsing JWT failed");
  }
}

Result<std::string> GetKeyId(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded_jwt) {
  try {
    return decoded_jwt.get_key_id();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Invalid JWT key id (kid) - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Invalid JWT key id (kid)");
  }
}

Result<std::string> GetIssuer(const decoded_jwt<kazuho_picojson>& decoded_jwt) {
  try {
    return decoded_jwt.get_issuer();
  } catch (const std::exception& e) {
    return STATUS(InvalidArgument, "Fetching issuer from the JWT failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching issuer from the JWT failed");
  }
}

Result<std::set<std::string>> GetAudiences(const decoded_jwt<kazuho_picojson>& decoded_jwt) {
  try {
    return decoded_jwt.get_audience();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching audience from the JWT failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching audience from the JWT failed");
  }
}

// Returns the claim value with the given name from the decoded jwt.
// Assumes that the claim value is either a string or an array of string. In both the cases, we
// return a vector<string> to the caller.
// In case the claim value isn't a string/array of string, an error is returned.
Result<std::vector<std::string>> GetClaimAsStringsArray(
    const decoded_jwt<kazuho_picojson>& decoded_jwt, const std::string& name) {
  try {
    std::vector<std::string> result;
    auto claim_value = decoded_jwt.get_payload_claim(name);

    auto claim_value_type = claim_value.get_type();
    switch (claim_value_type) {
      case type::string: {
        result.push_back(claim_value.as_string());
        break;
      }
      case type::array: {
        auto value_array = claim_value.as_array();
        if (value_array.empty()) {
          return result;
        }

        // Ensure that the type of the array element is a string and populate the result.
        if (kazuho_picojson::get_type(value_array[0]) == type::string) {
          for (const auto& e : value_array) {
            result.push_back(kazuho_picojson::as_string(e));
          }
          break;
        }

        // We reach here when the inner elements of the array aren't strings. So we fallthrough.
        FALLTHROUGH_INTENDED;
      }
      case type::boolean:
        FALLTHROUGH_INTENDED;
      case type::integer:
        FALLTHROUGH_INTENDED;
      case type::number:
        FALLTHROUGH_INTENDED;
      case type::object:
        return STATUS_FORMAT(
            InvalidArgument, "Claim value with name $0 was not a string or array of string.", name);
    }

    return result;
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Getting claim with name $0 from the JWT failed - $1", name, e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Getting claim with name $0 from the JWT failed", name);
  }
}

Result<std::string> GetAlgorithm(
    const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& decoded_jwt) {
  try {
    return decoded_jwt.get_algorithm();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching algorithm from the JWT failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching algorithm from the JWT failed");
  }
}

Result<verifier<jwt::default_clock, kazuho_picojson>> GetVerifier(
    const std::string& key_pem, const std::string& algo) {
  try {
    auto verifier = jwt::verify();

    // Algorithm names are case-sensitive.
    // Ref: https://datatracker.ietf.org/doc/html/rfc7517#section-4.4.
    //
    // We support two families of algorithms:
    // 1. RSA: RS256, RS384, RS512, PS256, PS384, PS512
    // 2. EC: ES256, ES256K, ES384, ES512
    //
    // We do not support HMAC family of algorithms such as HS256 since it falls in symmetric class
    // of algorithms and thus not safe for the users to share their keys in hba conf. This is OK
    // because almost all major IDPs use asymmetric keys for signing JWTs with RS256 being the most
    // widely used.
    // For e.g: Azure AD always uses asymmetric keys.
    if (algo == "RS256") {
      verifier.allow_algorithm(jwt::algorithm::rs256(key_pem));
    } else if (algo == "RS384") {
      verifier.allow_algorithm(jwt::algorithm::rs384(key_pem));
    } else if (algo == "RS512") {
      verifier.allow_algorithm(jwt::algorithm::rs512(key_pem));
    } else if (algo == "PS256") {
      verifier.allow_algorithm(jwt::algorithm::ps256(key_pem));
    } else if (algo == "PS384") {
      verifier.allow_algorithm(jwt::algorithm::ps384(key_pem));
    } else if (algo == "PS512") {
      verifier.allow_algorithm(jwt::algorithm::ps512(key_pem));
    } else if (algo == "ES256") {
      verifier.allow_algorithm(jwt::algorithm::es256(key_pem));
    } else if (algo == "ES384") {
      verifier.allow_algorithm(jwt::algorithm::es384(key_pem));
    } else if (algo == "ES512") {
      verifier.allow_algorithm(jwt::algorithm::es512(key_pem));
    } else if (algo == "ES256K") {
      verifier.allow_algorithm(jwt::algorithm::es256k(key_pem));
    } else {
      return STATUS_FORMAT(NotSupported, "Unsupported JWT algorithm: $0", algo);
    }

    return verifier;
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Constructing JWT verifier for public key: $0 and algo: $1 failed - $2",
        key_pem, algo, e.what());
  } catch (...) {
    return STATUS_FORMAT(
        InvalidArgument, "Constructing JWT verifier for public key: $0 and algo: $1 failed",
        key_pem, algo);
  }
}

Status VerifyJwtUsingVerifier(
    const verifier<jwt::default_clock, kazuho_picojson>& verifier,
    const decoded_jwt<kazuho_picojson>& decoded_jwt) {
  try {
    verifier.verify(decoded_jwt);
    return Status::OK();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Invalid JWT - $0", e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Invalid JWT");
  }
}

}  // namespace yb::util
