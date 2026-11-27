# Bundled MIBs

Standard MIBs that vendor MIBs commonly import, so an uploaded vendor MIB compiles without hunting for its
dependencies. They are also searchable on the Custom OIDs page.

- IETF MIBs (SNMPv2-SMI, SNMPv2-TC, SNMPv2-CONF, SNMPv2-MIB, RFC1155-SMI, RFC1213-MIB, RFC-1215, IF-MIB,
  IANAifType-MIB, SNMP-FRAMEWORK-MIB, INET-ADDRESS-MIB, HOST-RESOURCES-MIB, HOST-RESOURCES-TYPES, TCP-MIB, UDP-MIB,
  HCNUM-TC, IANA-ADDRESS-FAMILY-NUMBERS-MIB) and the Net-SNMP MIBs (UCD-SNMP-MIB, NET-SNMP-MIB, NET-SNMP-TC), as
  distributed with Net-SNMP (`mibs/` in https://github.com/net-snmp/net-snmp). IETF MIB modules are code components
  that may be reproduced under the IETF Trust's licence; the Net-SNMP MIBs are under Net-SNMP's BSD licence.
- `RFC-1212.txt` is a stub: RFC 1212 only defines the SMIv1 OBJECT-TYPE macro, which the compiler (pysmi) supplies.

To add another standard MIB that many vendor MIBs need, drop its text here as `<MODULE-NAME>.txt`.
