export default defineAppConfig({
  ui: {
    colors: {
      primary: 'teal',
      neutral: 'zinc'
    },
    footer: {
      slots: {
        root: 'border-t border-default',
        left: 'text-sm text-muted'
      }
    }
  },
  seo: {
    siteName: 'AuthEndpoints'
  },
  header: {
    title: '',
    to: '/',
    logo: {
      alt: 'AuthEndpoints',
      light: '',
      dark: ''
    },
    search: true,
    colorMode: true,
    links: [{
      'label': 'Changelog',
      'icon': 'i-lucide-scroll-text',
      'to': '/changelog',
      'aria-label': 'Changelog'
    }, {
      'icon': 'i-simple-icons-github',
      'to': 'https://github.com/madeyoga/AuthEndpoints',
      'target': '_blank',
      'aria-label': 'GitHub'
    }]
  },
  footer: {
    credits: `AuthEndpoints • MIT • © ${new Date().getFullYear()}`,
    colorMode: false,
    links: [{
      'icon': 'i-simple-icons-github',
      'to': 'https://github.com/madeyoga/AuthEndpoints',
      'target': '_blank',
      'aria-label': 'AuthEndpoints on GitHub'
    }, {
      'icon': 'i-simple-icons-nuget',
      'to': 'https://www.nuget.org/packages/AuthEndpoints/',
      'target': '_blank',
      'aria-label': 'AuthEndpoints on NuGet'
    }]
  },
  toc: {
    title: 'Table of Contents',
    bottom: {
      title: 'Community',
      edit: 'https://github.com/madeyoga/AuthEndpoints/edit/master/Documentation/content',
      links: [{
        icon: 'i-lucide-star',
        label: 'Star on GitHub',
        to: 'https://github.com/madeyoga/AuthEndpoints',
        target: '_blank'
      }, {
        icon: 'i-simple-icons-nuget',
        label: 'NuGet package',
        to: 'https://www.nuget.org/packages/AuthEndpoints/',
        target: '_blank'
      }]
    }
  }
})
