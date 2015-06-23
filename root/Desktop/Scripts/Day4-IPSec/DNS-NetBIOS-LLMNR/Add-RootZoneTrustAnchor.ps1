################################################################################
# The following command will add the DNSSEC root zone trust anchor information
# on Server 2012 and later.  Confirm that this information is still current at:
#      https://data.iana.org/root-anchors/root-anchors.xml
################################################################################

Add-DnsServerTrustAnchor -Name . -CryptoAlgorithm RsaSha256 -Digest 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5 -DigestType Sha256 -KeyTag 19036 


