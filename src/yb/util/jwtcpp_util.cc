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

#define OPENSSL_SUCCESS 1

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

Result<jwk<kazuho_picojson>> GetJwkFromJwks(jwks<kazuho_picojson> jwks, const std::string& key_id) {
  try {
    return jwks.get_jwk(key_id);
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Couldn't fetch key with id: $0 from JWKS - $1", key_id, e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Couldn't fetch key with id: $0 from JWKS", key_id);
  }
}

Result<std::string> GetX5cKeyValueFromJWK(jwk<kazuho_picojson> jwk) {
  try {
    return jwk.get_x5c_key_value();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Fetching x5c from JWK failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching x5c from JWK failed");
  }
}

Result<std::string> GetClaimFromJwkAsString(jwk<kazuho_picojson> jwk, const std::string& name) {
  try {
    return jwk.get_jwk_claim(name).as_string();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Fetching claim $0 from JWK failed - $1", name, e.what());
  } catch (...) {
    return STATUS_FORMAT(InvalidArgument, "Fetching claim $0 from JWK failed", name);
  }
}

Result<std::string> ConvertX5cDerToPem(const std::string& x5c) {
  try {
    return jwt::helper::convert_base64_der_to_pem(x5c);
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Converting JWT x5c to PEM format failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Converting JWT x5c to PEM format failed");
  }
}

Result<std::string> GetKeyAsPEM(const jwk<kazuho_picojson> jwk) {
  try {
    auto base64urlDecode = [](const std::string& base64url_encoded) {
      return jwt::base::decode<jwt::alphabet::base64url>(
          jwt::base::pad<jwt::alphabet::base64url>(base64url_encoded));
    };

    std::string key_type = jwk.get_key_type();
    if (key_type == "RSA") {
      auto n = VERIFY_RESULT(GetClaimFromJwkAsString(jwk, "n"));
      auto e = VERIFY_RESULT(GetClaimFromJwkAsString(jwk, "e"));

      auto modulus = base64urlDecode(n);
      auto exponent = base64urlDecode(e);

      BIGNUM* bnModulus = BN_bin2bn(
          pointer_cast<const unsigned char*>(modulus.data()), narrow_cast<int>(modulus.size()),
          nullptr /* ret */);
      BIGNUM* bnExponent = BN_bin2bn(
          pointer_cast<const unsigned char*>(exponent.data()), narrow_cast<int>(exponent.size()),
          nullptr /* ret */);
      if (bnModulus == nullptr || bnExponent == nullptr) {
        return STATUS(InvalidArgument, "Could not get modulus or exponent of RSA key.");
      }

      RSA* rsa_key = RSA_new();
      if(RSA_set0_key(rsa_key, bnModulus, bnExponent, NULL) != OPENSSL_SUCCESS) {
        return STATUS(InvalidArgument, "Failed to set modulus and exponent to RSA key");
      }

      EVP_PKEY* pkey = EVP_PKEY_new();
      auto res = EVP_PKEY_assign_RSA(pkey, rsa_key);
      if (res != OPENSSL_SUCCESS) {
        return STATUS(InvalidArgument, "Failed to assign private key");
      }

      BIO* pem_bio = BIO_new(BIO_s_mem());
      if (pem_bio == nullptr) {
        return STATUS(InternalError, "Could not create pem_bio");
      }

      if (PEM_write_bio_RSA_PUBKEY(pem_bio, rsa_key) != OPENSSL_SUCCESS) {
        return STATUS(InternalError, "Could not write RSA key into the pem_bio");
      }

      char* pem_data = nullptr;
      size_t pem_size = BIO_get_mem_data(pem_bio, &pem_data);
      std::string pem(pem_data, pem_size);

      BIO_free(pem_bio);
      EVP_PKEY_free(pkey);
      return pem;
    } else if (key_type == "EC") {
      auto x_claim = VERIFY_RESULT(GetClaimFromJwkAsString(jwk, "x"));
      auto y_claim = VERIFY_RESULT(GetClaimFromJwkAsString(jwk, "y"));
      auto curve_name = VERIFY_RESULT(GetClaimFromJwkAsString(jwk, "crv"));

      auto x_coordinate = base64urlDecode(x_claim);
      auto y_coordinate = base64urlDecode(y_claim);

      auto nid = EC_curve_nist2nid(curve_name.c_str());
      if (nid == NID_undef) {
        // P-256K aka secp256k1 is not included in the openssl's list of nist2nid lookup table via
        // EC_curve_nist2nid.
        //
        // It is present in the lookup table used in ossl_ec_curve_name2nid function but that is not
        // exposed publicly.
        //
        // So we set a hardcoded value as a hack. This is fine because the NIDs are public values
        // i.e. they shouldn't change between stable releases of openssl.
        if (curve_name == "P-256K" || curve_name == "secp256k1") {
          nid = NID_secp256k1;
        } else {
          return STATUS_FORMAT(
              InvalidArgument, "Could not determine the NID for curve name: $0", curve_name);
        }
      }

      EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
      if (ec_key == nullptr) {
        return STATUS_FORMAT(
            InvalidArgument, "Could not create EC_KEY with curve name $0 and nid $1.", curve_name,
            nid);
      }

      BIGNUM* x = BN_bin2bn(
          reinterpret_cast<const unsigned char*>(x_coordinate.data()),
          narrow_cast<int>(x_coordinate.size()), nullptr);
      BIGNUM* y = BN_bin2bn(
          reinterpret_cast<const unsigned char*>(y_coordinate.data()),
          narrow_cast<int>(y_coordinate.size()), nullptr);
      if (x == nullptr || y == nullptr) {
        return STATUS(InvalidArgument, "Could not get x or y coordinates of EC key.");
      }

      if (EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) != OPENSSL_SUCCESS) {
        return STATUS(InvalidArgument, "Could not set public key affine coordinates.");
      }
      EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

      BIO* pem_bio = BIO_new(BIO_s_mem());
      if (pem_bio == nullptr) {
        return STATUS(InternalError, "Could not create pem_bio.");
      }

      if (PEM_write_bio_EC_PUBKEY(pem_bio, ec_key) != OPENSSL_SUCCESS) {
        return STATUS(InternalError, "Could not write EC key into the pem_bio.");
      }

      char* pem_data = nullptr;
      size_t pem_size = BIO_get_mem_data(pem_bio, &pem_data);
      std::string pem(pem_data, pem_size);

      BIO_free(pem_bio);
      EC_KEY_free(ec_key);
      BN_free(x);
      BN_free(y);
      return pem;
    }

    return STATUS(NotSupported, "Unsupported kty. Only RSA and EC are supported.");
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Converting JWK to PEM format failed with error $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Converting JWK to PEM format failed");
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

Result<std::string> GetKeyId(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> decoded_jwt) {
  try {
    return decoded_jwt.get_key_id();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(InvalidArgument, "Invalid JWT key id (kid): $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Invalid JWT key id (kid)");
  }
}

Result<std::string> GetIssuer(const decoded_jwt<kazuho_picojson> decoded_jwt) {
  try {
    return decoded_jwt.get_issuer();
  } catch (const std::exception& e) {
    return STATUS(InvalidArgument, "Fetching issuer from the JWT failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching issuer from the JWT failed");
  }
}

Result<std::set<std::string>> GetAudiences(const decoded_jwt<kazuho_picojson> decoded_jwt) {
  try {
    return decoded_jwt.get_audience();
  } catch (const std::exception& e) {
    return STATUS_FORMAT(
        InvalidArgument, "Fetching audience from the JWT failed - $0", e.what());
  } catch (...) {
    return STATUS(InvalidArgument, "Fetching audience from the JWT failed");
  }
}

// Returns the claim value with the given name from the decoded jwt.
// Assumes that the claim value is either a string or an array of string. In both the cases, we
// return a vector<string> to the caller.
// In case the claim value isn't a string/array of string, an error is returned.
Result<std::vector<std::string>> GetClaimAsStringsArray(
    const decoded_jwt<kazuho_picojson> decoded_jwt, const std::string& name) {
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
    const decoded_jwt<kazuho_picojson> decoded_jwt) {
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
