select jwt.decode_jwt(
    token := :token,
    keys := jsonb_build_array(
       jwt.jwk_to_key(:bigexp_jwk),
       jwt.jwk_to_key(:good_jwk)
    )
) as decode_jwt_rsa_bigexp;
