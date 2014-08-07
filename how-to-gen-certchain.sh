

function random()
{
    min=$1;
    max=$2-$1;
    num=$(date +%s+%N);
    ((retnum=num%max+min));
    echo $retnum;
  
}


DIR=~/android_ca/private

rm sign.keystore
rm sign.*

out=$(random 2 10000);
echo $out > ~/android_ca/serial

openssl genrsa -3 -out $DIR/cakey.pem   2048

openssl req -new -x509 -days 36500 -key $DIR/cakey.pem -out $DIR/cacert.pem -subj '/C=US/ST=California/L=San Jose/O=Adobe Systems Incorporated/OU=Information Systems/CN=Adobe Systems Incorporated'

keytool -genkey -keyalg RSA -alias sign -keystore sign.keystore -storepass android -storetype jks

keytool -certreq -alias sign -keyalg RSA -file sign.csr -keystore sign.keystore

openssl  ca   -in sign.csr -out sign.pem  -config ./gen_ca.conf


openssl x509 -in sign.pem -out sign.cer


keytool -import -alias ca -trustcacerts -file /home/retme/android_ca/private/cacert.pem -keystore sign.keystore;
keytool -import -alias sign  -trustcacerts -file  sign.cer -keystore sign.keystore
jarsigner -verbose -keystore sign.keystore  -storepass android -keypass android -signedjar  ../noperm_new.apk  ../noperm.apk sign
