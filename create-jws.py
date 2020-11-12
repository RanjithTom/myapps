import click
import boto3
import base64
import array
import time
import json
import jwcrypto.jwk as jwk
import binascii
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

apiDomainName = {'uat': 'api.uat.ciam.tech-03.net', 'prod': 'api.ciam.dnb.no'}

@click.command()
@click.option(
    "-e",
    "--environment",
    envvar="ENVIRONMENT",
    required=True,
    help="The environment to deploy to",
)
@click.option(
    "-c",
    "--client_name",
    envvar="CLIENTNAME",
    required=True,
    help="The name of the client for which jwks has to be generated",
)
def main(environment, client_name):
    key_arn = create_kms_key(client_name)
    pub_key_jwk = get_public_key(key_arn)
    jwt_header = get_header()
    jwt_payload = create_jwt_payload(environment, pub_key_jwk)
    client_jws = create_jws(key_arn, jwt_payload, jwt_header)
    print(
        f"""
            arn={key_arn}
            client_jws={client_jws.decode('ascii')} 
        """
    )

def create_kms_key(client_name):
    kms_client = boto3.client("kms", region_name="eu-west-1")
    create_key_response = kms_client.create_key(
        Description=f"Automatically generated key for {client_name}",
        KeyUsage="SIGN_VERIFY",
        CustomerMasterKeySpec="ECC_NIST_P256",
    )
    return create_key_response["KeyMetadata"]["Arn"]

def get_public_key(key_arn):
    kms_client = boto3.client("kms", region_name="eu-west-1")
    get_pub_key_response = kms_client.get_public_key(KeyId=key_arn)
    pub_key_raw_bytes = base64.b64encode(get_pub_key_response["PublicKey"])
    pub_key_raw_string = pub_key_raw_bytes.decode("ascii")
    pub_key_pkcs8_string = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----".format(
        pub_key_raw_string
    )
    pub_key_pkcs8_bytes = bytearray()
    pub_key_pkcs8_bytes.extend(map(ord, pub_key_pkcs8_string))
    pub_key = jwk.JWK.from_pem(data=pub_key_pkcs8_bytes)
    return pub_key.export_public()

def create_jwt_payload(environment, pub_key_jwk):
    iat = lambda: int(time.time()) #current timestamp in CET
    exp = iat() + (30 * 24 * 3600) # valid to the next 30 days from iat
    aud = 'https://{}/clients/v1'.format(apiDomainName[environment])
    jwk = {'jwk': json.loads(pub_key_jwk)}
    payload = {'aud': aud, 'cnf': jwk, 'exp': exp, 'iat': iat()}
    payloadBytes = force_bytes(json.dumps(payload, separators=(",", ":")))
    return base64url_encode(payloadBytes)

def get_header():
    header = {"alg": "ES256"}
    json_header = force_bytes(json.dumps(header, separators=(",", ":")))
    return base64url_encode(json_header)

def create_jws(key_arn, payload, header):
    # Segments
    segments = []
    segments.append(header)
    segments.append(payload)
    signing_input = b".".join(segments)
    jwt_signature = sign_jwt(key_arn, signing_input)
    verify_jwt_response = verify_jwt(key_arn, signing_input, jwt_signature)
    if (verify_jwt_response['SignatureValid']):
        segments.append(convert_ECDSA_signature_to_base64(jwt_signature))
        return b".".join(segments)
    else:
        print("Could not generate jws for the client")

def sign_jwt(key_arn, jwt_payload):
    kms_client = boto3.client("kms", region_name="eu-west-1")
    sign_jwt_response = kms_client.sign(
        KeyId=key_arn,
        Message=jwt_payload,
        MessageType='RAW',
        SigningAlgorithm='ECDSA_SHA_256'
    )
    return sign_jwt_response["Signature"]

def verify_jwt(key_arn, message, signature):
    kms_client = boto3.client("kms", region_name="eu-west-1")
    response = kms_client.verify (
        KeyId=key_arn,
        Message=message,
        MessageType='RAW',
        Signature=signature,
        SigningAlgorithm='ECDSA_SHA_256',
    )
    return response

def force_bytes(value):
    if isinstance(value, str):
        return value.encode("ascii")
    elif isinstance(value, bytes):
        return value
    else:
        raise TypeError("Expected a string value")

def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b"=", b"")

def convert_ECDSA_signature_to_base64(signature):
    num_bits = 256
    num_bytes = (num_bits + 7) // 8
    r, s = decode_dss_signature(signature)
    rawsig =  number_to_bytes(r, num_bytes) + number_to_bytes(s, num_bytes)
    return base64url_encode(rawsig)

def number_to_bytes(num, num_bytes):
    padded_hex = "%0*x" % (2 * num_bytes, num)
    big_endian = binascii.a2b_hex(padded_hex.encode("ascii"))
    return big_endian

if __name__ == "__main__":
    main()