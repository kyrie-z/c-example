

生成私钥和自签名证书
openssl req -new -x509 -newkey rsa:2048 -subj "/CN=PKCS7 test Root CA/" -keyout root.key -out root.crt -days 3650 -nodes -sha256


签名生成pkcs7-sign.p7s文件
openssl smime -sign -in pkcs7-sign -inkey root.key -outform DER -binary -signer root.crt -out pkcs7-sign.p7s

读取pkcs7-sign.p7s文件信息(查看签名后pkcs7结构信息)
openssl cms -inform DER -in pkcs7-sign.p7s -noout -cmsout -print