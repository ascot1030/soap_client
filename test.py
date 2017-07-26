from wsse import encryption

# encryption
plain = open('test/fplain.xml','rb').read()
encrd,key = encryption.encrypt(plain,'test/cert.pem')
# print(encrd.decode('utf-8'))
# decryption
# encrd = open('fencrypted.xml','rb').read()
print(encryption.decrypt(envelope=encrd,keyfile='test/key.pem',key=key))