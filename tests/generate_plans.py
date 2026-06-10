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
import hashlib
import hmac
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

    # 1e308 is finite JSON but overflows PostgreSQL's timestamp range; the
    # exp/nbf checks must reject it rather than letting to_timestamp raise.
    overflow_epoch = 1e308

    # Exercised through decode_jwt with default validation (exp/nbf enforced).
    claimsTests = {
        "exp_valid": claims_vector({"aud": "postgresql", "exp": far_future}),
        "exp_expired": claims_vector({"aud": "postgresql", "exp": far_past}),
        "nbf_valid": claims_vector({"aud": "postgresql", "nbf": far_past}),
        "nbf_future": claims_vector({"aud": "postgresql", "nbf": far_future}),
        "exp_overflow": claims_vector({"aud": "postgresql", "exp": overflow_epoch}),
        "nbf_overflow": claims_vector({"aud": "postgresql", "nbf": overflow_epoch}),
    }
    # Exercised through decode_jwt with audience := 'postgresql'. The trailing
    # cases pin down the audience check against malformed `aud` claims: a JSON
    # null and a number must both be rejected (a number that stringifies to the
    # expected audience must not be accepted through `->>`).
    claimsAudTests = {
        "aud_match": claims_vector({"aud": "postgresql"}),
        "aud_match_array": claims_vector({"aud": ["other", "postgresql"]}),
        "aud_mismatch": claims_vector({"aud": "other"}),
        "aud_absent": claims_vector({"sub": "user"}),
        "aud_null": claims_vector({"aud": None}),
        "aud_number": claims_vector({"aud": 123}),
    }
    # Exercised through decode_jwt with issuer := 'https://example.com'.
    claimsIssTests = {
        "iss_match": claims_vector({"iss": "https://example.com"}),
        "iss_mismatch": claims_vector({"iss": "https://evil.example.com"}),
        "iss_absent": claims_vector({"sub": "user"}),
    }

    # Security-property vectors. Each case is fed to decode_jwt with a single
    # key and, apart from the positive control, must be rejected (return null).
    # These pin down the resistance to the well-known JWT attacks: the unsigned
    # `alg: none` token, RSA->HMAC algorithm confusion (an HS256 token forged
    # using the published RSA public key as the HMAC secret), verification
    # against the wrong key, signature stripping/tampering, structurally
    # malformed tokens, and validly-signed but non-object payloads.

    def b64u(data: bytes) -> str:
        """URL-safe base64 without padding, matching the JWT segment encoding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def hs256_raw(payload: bytes, secret: bytes) -> str:
        """Sign an arbitrary (possibly non-object) payload as an HS256 JWT.

        joserfc's encoder only accepts an object claims set, so the payload is
        assembled and HMAC-signed by hand to cover the malformed-payload cases.
        """
        signing_input = f'{b64u(json.dumps({"alg": "HS256"}).encode())}.{b64u(payload)}'
        signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{b64u(signature)}"

    # The legitimate key the server trusts, plus a second, unrelated key used to
    # prove a token does not verify against a key it was not signed with.
    sec_kid = str(uuid4())
    sec_key = jwk.OctKey.generate_key(
        key_size=256,
        parameters={"alg": "HS256", "use": "sig", "kid": sec_kid},
    )
    sec_jwk = json.dumps(sec_key.as_dict())
    sec_secret = base64.urlsafe_b64decode(sec_key.as_dict()["k"] + "==")

    other_kid = str(uuid4())
    other_key = jwk.OctKey.generate_key(
        key_size=256,
        parameters={"alg": "HS256", "use": "sig", "kid": other_kid},
    )
    other_jwk = json.dumps(other_key.as_dict())

    # An RSA key whose public part the server publishes. An attacker who only
    # knows the public key tries to forge an HS256 token using the PEM-encoded
    # public key as the HMAC secret; the key's own `alg` (RS256) must keep it
    # from ever being used to verify an HS256 token.
    sec_rsa_kid = str(uuid4())
    sec_rsa_key = jwk.RSAKey.generate_key(
        key_size=2048,
        parameters={"alg": "RS256", "use": "sig", "kid": sec_rsa_kid},
    )
    sec_rsa_jwk = json.dumps(sec_rsa_key.as_dict(private=False))
    rsa_pub_pem = sec_rsa_key.as_pem(private=False)

    # A genuine HS256 token signed with the trusted key (positive control).
    valid_token = jwt.encode(
        header={"alg": "HS256", "kid": sec_kid},
        claims={"aud": "postgresql"},
        key=sec_key,
        algorithms=["HS256"],
        registry=registry,
    )
    v_header, v_payload, v_signature = valid_token.split(".")

    # alg: none, carrying privileged-looking claims and an empty signature.
    none_token = (
        f'{b64u(json.dumps({"alg": "none", "kid": sec_kid}).encode())}.'
        f'{b64u(json.dumps({"aud": "postgresql", "sub": "admin"}).encode())}.'
    )

    # HS256 token forged with the RSA public PEM as the HMAC secret.
    confusion_input = (
        f'{b64u(json.dumps({"alg": "HS256", "kid": sec_rsa_kid}).encode())}.'
        f'{b64u(json.dumps({"aud": "postgresql", "sub": "admin"}).encode())}'
    )
    confusion_sig = hmac.new(
        rsa_pub_pem, confusion_input.encode(), hashlib.sha256
    ).digest()
    confusion_token = f"{confusion_input}.{b64u(confusion_sig)}"

    # Flip the final character of a valid signature to corrupt it.
    tampered_sig = v_signature[:-1] + ("A" if v_signature[-1] != "A" else "B")

    securityTests = {
        "valid_control": {"token": valid_token, "jwk": sec_jwk},
        "alg_none": {"token": none_token, "jwk": sec_rsa_jwk},
        "alg_confusion_rsa_hmac": {"token": confusion_token, "jwk": sec_rsa_jwk},
        "wrong_key": {"token": valid_token, "jwk": other_jwk},
        "tampered_signature": {
            "token": f"{v_header}.{v_payload}.{tampered_sig}",
            "jwk": sec_jwk,
        },
        "stripped_signature": {"token": f"{v_header}.{v_payload}.", "jwk": sec_jwk},
        "two_segments": {"token": f"{v_header}.{v_payload}", "jwk": sec_jwk},
        "one_segment": {"token": "not-a-jwt", "jwk": sec_jwk},
        "garbage_segments": {"token": "@@@.###.$$$", "jwk": sec_jwk},
        "payload_scalar": {"token": hs256_raw(b'"admin"', sec_secret), "jwk": sec_jwk},
        "payload_array": {"token": hs256_raw(b"[1,2,3]", sec_secret), "jwk": sec_jwk},
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

    # Write the security-property test dictionary to its 'yaml' file
    with PLANS_PATH.joinpath("decode_jwt_security.yaml").open("wt") as f:
        yaml.safe_dump(data=securityTests, stream=f, width=BIGINT)


if __name__ == "__main__":
    main()
