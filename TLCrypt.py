#!/usr/bin/env python3

def TLARCCrypt(p):
    key = "Ei2HNryt8ysSdRRI54XNQHBEbOIRqNjQgYxsTmuW3srSVRVFyLh8mwvhBLPFQph3ecDMLnDtjDUdrUwt7oTsJuYl72hXESNiD6jFIQCtQN1unsmn3JXjeYwGJ55pqTkVyN2OOm3vekF6G1LM4t3kiiG4lGwbxG4CG1s5Sli7gcINFBOLXQnPpsQNWDmPbOm74mE7eyR3L7tk8tUhI17FLKm11hrrd1ck74bMw3VYSK3X5RrDgXelewMU6o1tJ3iX"

    S = list(range(256))
    j = 0
    out = bytearray()

    #KSA Phase
    for i in range(256):
        j = (j + S[i] + ord(key[i])) % 256
        S[i] , S[j] = S[j] , S[i]

    #PRGA Phase
    i = j = 0
    for char in p:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        out.append((char ^ S[(S[i] + S[j]) % 256]))

    return out
    