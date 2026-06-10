select jwt.decode_jwt(
    token := :token,
    keys := jsonb_build_array(
       jwt.jwk_to_key(:bad_jwk),
       jwt.jwk_to_key(:good_jwk)
    )
) as decode_jwt_malformed_key;
