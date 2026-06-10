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


if __name__ == "__main__":
    main()
