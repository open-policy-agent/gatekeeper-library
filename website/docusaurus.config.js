// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer').themes.github;
const darkCodeTheme = require('prism-react-renderer').themes.dracula;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Gatekeeper Library',
  tagline: 'Policy Controller for Kubernetes',
  url: 'https://open-policy-agent.github.io',
  baseUrl: '/gatekeeper-library/website/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'open-policy-agent', // Usually your GitHub org/user name.
  projectName: 'gatekeeper-library', // Usually your repo name.

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl:
            'https://github.com/open-policy-agent/gatekeeper-library/edit/master/website',
          routeBasePath: '/',
          sidebarCollapsed: true
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
        gtag: {
          trackingID: 'G-RX9N8G7RS5',
          anonymizeIP: true,
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      algolia: {
        appId: '50R2XL9XTU',
        apiKey: 'c6cf0797aa351ac2c8640899d40c8821',
        indexName: 'gatekeeper-library-web',
      },
      colorMode: {
        defaultMode: 'light',
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'Gatekeeper Library',
        logo: {
          alt: 'Gatekeeper logo',
          src: 'img/logo.svg',
          href: 'https://open-policy-agent.github.io/gatekeeper-library/',
        },
        items: [
          {
            href: 'https://github.com/open-policy-agent/gatekeeper-library',
            position: 'right',
            className: 'header-github-link',
            'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Community',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/open-policy-agent/gatekeeper-library',
              },
              {
                label: 'Slack',
                href: 'https://openpolicyagent.slack.com/messages/CDTN970AX',
              },
              {
                label: 'Meetings',
                href: 'https://docs.google.com/document/d/1A1-Q-1OMw3QODs1wT6eqfLTagcGmgzAJAjJihiO3T48/edit)',
              },
            ],
          },
        ],
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
};

module.exports = config;
