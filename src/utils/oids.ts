export const OID_MAP: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10045.3.1.7': 'prime256v1',
  '1.3.132.0.34': 'secp384r1',
  '1.3.132.0.35': 'secp521r1',
  '2.5.4.3': 'commonName',
  '2.5.4.4': 'surname',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'countryName',
  '2.5.4.7': 'localityName',
  '2.5.4.8': 'stateOrProvinceName',
  '2.5.4.9': 'streetAddress',
  '2.5.4.10': 'organizationName',
  '2.5.4.11': 'organizationalUnitName',
  '2.5.4.12': 'title',
  '2.5.4.13': 'description',
  '2.5.4.15': 'businessCategory',
  '2.5.4.17': 'postalCode',
  '2.5.4.41': 'name',
  '2.5.4.42': 'givenName',
  '2.5.4.43': 'initials',
  '2.5.4.44': 'generationQualifier',
  '2.5.4.46': 'dnQualifier',
  '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionCountryName',
  '2.5.29.14': 'subjectKeyIdentifier',
  '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.31': 'cRLDistributionPoints',
  '2.5.29.32': 'certificatePolicies',
  '2.5.29.35': 'authorityKeyIdentifier',
  '2.5.29.37': 'extKeyUsage',
  '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
  '1.3.6.1.5.5.7.1.11': 'subjectInfoAccess',
  '1.3.6.1.5.5.7.1.3': 'qualifiedCertificateStatements',
  '1.3.6.1.5.5.7.48.1': 'OCSP',
  '1.3.6.1.5.5.7.48.2': 'caIssuers',
  '2.5.29.9': 'subjectDirectoryAttributes',
  '2.5.29.30': 'nameConstraints',
  '2.5.29.33': 'policyMappings',
  '2.5.29.36': 'policyConstraints',
  '2.5.29.46': 'freshestCRL',
  '2.5.29.54': 'inhibitAnyPolicy',
  '1.3.6.1.4.1.11129.2.4.2': 'CT Precertificate SCTs',
  '1.3.6.1.4.1.11129.2.4.3': 'CT Precertificate Poison',
  '2.23.140.1.2.1': 'domainValidated',
  '2.23.140.1.2.2': 'organizationValidated',
  '2.23.140.1.2.3': 'extendedValidation',
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
};

export function lookupOID(oid: string): string {
  return OID_MAP[oid] || oid;
}

export function oidToLongName(oid: string): string {
  const map: Record<string, string> = {
    '2.5.4.3': 'CN',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.5': 'serialNumber',
    '2.5.4.9': 'street',
    '2.5.4.17': 'postalCode',
    '2.5.4.42': 'GN',
    '2.5.4.4': 'SN',
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
  };
  return map[oid] || OID_MAP[oid] || oid;
}

const OID_TO_DOTTED: Record<string, string> = {};
const DOTTED_TO_OID: Record<string, string> = {};

export function oidShortName(oid: string): string {
  return oidToLongName(oid);
}
