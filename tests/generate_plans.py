#
# MIT License
#
# Copyright (c) 2023 Leandro Lima <leandro@lls-software.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
import base64
import json
from pathlib import Path
from uuid import uuid4

import yaml
from joserfc import jwk, jwt
from joserfc.rfc7797 import JWSRegistry

BIGINT = 2147483647

PLANS_PATH = Path(__file__).parent / "regresql" / "plans"

BAD_PAYLOAD = "eyJhdWQiOiJwMHN0Z3Jlc3FsIn0"  # {"aud":"p0stgresql"}


def main() -> None:
    """Generate test vectors for HMAC and RSA JWTs.

    The test vectors are written to the 'decode_jwt_hmac.yaml' and
    'decode_jwt_rsa.yaml' files in the 'plans' directory.

    :raises ValueError: If an unsupported algorithm is encountered.
    """
    # Generate a list of algorithms in the format 'HS256', 'HS384', 'RS256', etc.
    algorithms = sorted(
        alg for shaBits in (256, 384, 512) for alg in (f"HS{shaBits}", f"RS{shaBits}")
    )

    # Create a JWSRegistry object with the generated algorithms
    registry = JWSRegistry(algorithms=algorithms)

    # Initialize empty dictionaries for HMAC and RSA tests
    rsaTests = {}
    rsaFailTests = {}
    hmacTests = {}
    hmacFailTests = {}

    # Iterate over each algorithm
    for alg in algorithms:
        # Generate a random key identifier
        kid = str(uuid4())

        # If the algorithm starts with 'HS', generate an OctKey
        if alg.startswith("HS"):
            key = jwk.OctKey.generate_key(
                key_size=int(alg[2:]),
                parameters={"alg": alg, "use": "sig", "kid": kid},
            )
        # If the algorithm starts with 'RS', generate an RSAKey
        elif alg.startswith("RS"):
            key = jwk.RSAKey.generate_key(
                key_size=int(alg[2:]) * 8,
                parameters={"alg": alg, "use": "sig", "kid": kid},
            )
        else:
            # If the algorithm is not supported, raise a ValueError
            raise ValueError(f"Unsupported alg: {alg}")

        # Encode a JWT token with the generated key and algorithm
        token = jwt.encode(
            header={"alg": alg, "kid": kid},
            claims={"aud": "postgresql"},
            key=key,
            algorithms=[alg],
            registry=registry,
        )

        # If the algorithm is HMAC, add the token and key to the HMAC tests dictionary
        if alg.startswith("HS"):
            hmacTests[alg.lower()] = {"token": token, "jwk": json.dumps(key.as_dict())}
            header, payload, signature = token.split(".")
            hmacFailTests[alg.lower()] = {
                "token": f"{header}.{BAD_PAYLOAD}.{signature}",
                "jwk": json.dumps(key.as_dict()),
            }
        # If the algorithm is RSA, add the token and key (excluding private key) to the RSA tests dictionary
        elif alg.startswith("RS"):
            rsaTests[alg.lower()] = {"token": token, "jwk": json.dumps(key.as_dict(private=False))}
            header, payload, signature = token.split(".")
            rsaFailTests[alg.lower()] = {
                "token": f"{header}.{BAD_PAYLOAD}.{signature}",
                "jwk": json.dumps(key.as_dict(private=False)),
            }
        else:
            # If the algorithm is not supported, raise a ValueError
            raise ValueError(f"Unsupported alg: {alg}")

    # The RS* algorithms only fix the digest, not the RSA key size, so generate
    # additional vectors where the modulus size differs from the digest size
    # (e.g. RS256 signed with a 4096-bit key). These guard against regressions
    # that assume a fixed signature length per algorithm.
    crossSizes = {"RS256": 4096, "RS384": 2048, "RS512": 2048}
    for alg, keySizeBits in crossSizes.items():
        kid = str(uuid4())
        key = jwk.RSAKey.generate_key(
            key_size=keySizeBits,
            parameters={"alg": alg, "use": "sig", "kid": kid},
        )
        token = jwt.encode(
            header={"alg": alg, "kid": kid},
            claims={"aud": "postgresql"},
            key=key,
            algorithms=[alg],
            registry=registry,
        )
        name = f"{alg.lower()}_{keySizeBits}"
        rsaTests[name] = {"token": token, "jwk": json.dumps(key.as_dict(private=False))}
        header, payload, signature = token.split(".")
        rsaFailTests[name] = {
            "token": f"{header}.{BAD_PAYLOAD}.{signature}",
            "jwk": json.dumps(key.as_dict(private=False)),
        }

    # Claims-validation vectors. These exercise the exp/nbf/aud/iss checks that
    # decode_jwt performs after verifying the signature. Fixed epoch values keep
    # the vectors deterministic regardless of when the suite runs.
    far_past = 1  # 1970-01-01, always in the past
    far_future = 7258118400  # 2200-01-01, always in the future

    claims_kid = str(uuid4())
    claims_key = jwk.OctKey.generate_key(
        key_size=256,
        parameters={"alg": "HS256", "use": "sig", "kid": claims_kid},
    )

    def claims_vector(claims: dict) -> dict:
        """Sign a token carrying the given claims with the shared HMAC key."""
        token = jwt.encode(
            header={"alg": "HS256", "kid": claims_kid},
            claims=claims,
            key=claims_key,
            algorithms=["HS256"],
            registry=registry,
        )
        return {"token": token, "jwk": json.dumps(claims_key.as_dict())}

    # Exercised through decode_jwt with default validation (exp/nbf enforced).
    claimsTests = {
        "exp_valid": claims_vector({"aud": "postgresql", "exp": far_future}),
        "exp_expired": claims_vector({"aud": "postgresql", "exp": far_past}),
        "nbf_valid": claims_vector({"aud": "postgresql", "nbf": far_past}),
        "nbf_future": claims_vector({"aud": "postgresql", "nbf": far_future}),
    }
    # Exercised through decode_jwt with audience := 'postgresql'.
    claimsAudTests = {
        "aud_match": claims_vector({"aud": "postgresql"}),
        "aud_match_array": claims_vector({"aud": ["other", "postgresql"]}),
        "aud_mismatch": claims_vector({"aud": "other"}),
        "aud_absent": claims_vector({"sub": "user"}),
    }
    # Exercised through decode_jwt with issuer := 'https://example.com'.
    claimsIssTests = {
        "iss_match": claims_vector({"iss": "https://example.com"}),
        "iss_mismatch": claims_vector({"iss": "https://evil.example.com"}),
        "iss_absent": claims_vector({"sub": "user"}),
    }

    # A key whose RSA exponent exceeds the supported int range must be skipped
    # gracefully rather than raising. Pairing such a key with a valid one in the
    # same set proves the oversized key does not poison verification.
    big_exp_kid = str(uuid4())
    big_exp_key = jwk.RSAKey.generate_key(
        key_size=2048,
        parameters={"alg": "RS256", "use": "sig", "kid": big_exp_kid},
    )
    big_exp_token = jwt.encode(
        header={"alg": "RS256", "kid": big_exp_kid},
        claims={"aud": "postgresql"},
        key=big_exp_key,
        algorithms=["RS256"],
        registry=registry,
    )
    good_jwk = big_exp_key.as_dict(private=False)
    oversized_jwk = dict(good_jwk)
    # 2 ** 40 + 1 does not fit in a signed 32-bit integer.
    oversized_jwk["e"] = (
        base64.urlsafe_b64encode((2**40 + 1).to_bytes(6, "big")).rstrip(b"=").decode()
    )
    rsaBigExpTests = {
        "skips_oversized_exponent": {
            "token": big_exp_token,
            "bigexp_jwk": json.dumps(oversized_jwk),
            "good_jwk": json.dumps(good_jwk),
        }
    }

    # Write the HMAC tests dictionary to 'decode_jwt_hmac.yaml' file
    with PLANS_PATH.joinpath("decode_jwt_hmac.yaml").open("wt") as f:
        yaml.safe_dump(data=hmacTests, stream=f, width=BIGINT)

    # Write the HMAC fail tests dictionary to 'decode_jwt_hmac_fail.yaml' file
    with PLANS_PATH.joinpath("decode_jwt_hmac_fail.yaml").open("wt") as f:
        yaml.safe_dump(data=hmacFailTests, stream=f, width=BIGINT)

    # Write the RSA tests dictionary to 'decode_jwt_rsa.yaml' file
    with PLANS_PATH.joinpath("decode_jwt_rsa.yaml").open("wt") as f:
        yaml.safe_dump(data=rsaTests, stream=f, width=BIGINT)

    # Write the RSA fail tests dictionary to 'decode_jwt_rsa_fail.yaml' file
    with PLANS_PATH.joinpath("decode_jwt_rsa_fail.yaml").open("wt") as f:
        yaml.safe_dump(data=rsaFailTests, stream=f, width=BIGINT)

    # Write the claims-validation test dictionaries to their 'yaml' files
    with PLANS_PATH.joinpath("decode_jwt_claims.yaml").open("wt") as f:
        yaml.safe_dump(data=claimsTests, stream=f, width=BIGINT)

    with PLANS_PATH.joinpath("decode_jwt_claims_aud.yaml").open("wt") as f:
        yaml.safe_dump(data=claimsAudTests, stream=f, width=BIGINT)

    with PLANS_PATH.joinpath("decode_jwt_claims_iss.yaml").open("wt") as f:
        yaml.safe_dump(data=claimsIssTests, stream=f, width=BIGINT)

    # Write the oversized-exponent test dictionary to its 'yaml' file
    with PLANS_PATH.joinpath("decode_jwt_rsa_bigexp.yaml").open("wt") as f:
        yaml.safe_dump(data=rsaBigExpTests, stream=f, width=BIGINT)


if __name__ == "__main__":
    main()
