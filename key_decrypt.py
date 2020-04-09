#!/usr/bin/env python3 

def decrypt(input):
    out = []
    for i in input:
        out += [0x1c ^ i]
    return out

encrypted_key_hex = ["7f","6f","79","2f","2a","2f","73","7a","7a","6f","79","7f","2e","2c","2e","2c"]
encrypted_success_hex = ["48","74","79","3c","77","79","65","3c","75","6f","3c","7f","73","6e","6e","79","7f","68","32","3c","5f","73","72","7b","6e","7d","68","69","70","7d","68","75","73","72","6f","3d"]
encrypted_key = [int(''.join(c),16) for c in encrypted_key_hex ]
encrypted_success = [int(''.join(c),16) for c in encrypted_success_hex ]
key = "".join(chr(c) for c in decrypt(encrypted_key))
success = "".join(chr(c) for c in decrypt(encrypted_success))
print(key)
print(success)




