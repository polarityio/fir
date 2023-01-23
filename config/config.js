module.exports = {
  name: 'Fast Incident Response (FIR) Search',
  acronym: 'FIR',
  description: 'Searches Fast Incident Response (FIR) for artifacts contained within cybersecurity incidents.',
  entityTypes: ['ipv4', 'hash', 'domain', 'email'],
  defaultColor: 'light-purple',
  logging: { level: 'info' },
  block: {
    component: {
      file: './components/fir.js'
    },
    template: {
      file: './templates/fir.hbs'
    }
  },
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/styles.less'],
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',
    /**
     * If set to false, the integration will ignore SSL errors.  This will allow the integration to connect
     * to the server without valid SSL certificates.  Please note that we do NOT recommending setting this
     * to false in a production environment.
     */
    rejectUnauthorized: true
  },
  options: [
    {
      key: 'url',
      name: 'FIR Server URL',
      description:
        'The URL for your FIR instance to include the schema (i.e., https://) and port (e.g., https://fir:8000) as necessary',
      type: 'text',
      default: '',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'apiKey',
      name: 'FIR User REST API Token',
      description: 'The REST API Token used to authenticate to your FIR instance.',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'blocklist',
      name: 'Ignore Entities',
      description: 'Comma delimited list of indicators you do not want looked up.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'domainBlocklistRegex',
      name: 'Ignore Domain Regex',
      description: 'Domains that match the given regex will not be looked up.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'ipBlocklistRegex',
      name: 'Ignore IP Regex',
      description: 'IPs that match the given regex will not be looked up.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
