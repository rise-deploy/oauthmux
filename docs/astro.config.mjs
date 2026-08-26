import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://rise-deploy.github.io',
  base: '/oauthmux',
  integrations: [
    starlight({
      title: 'oauthmux',
      description: 'Stable OAuth callbacks and explicit OIDC relay boundaries.',
      customCss: ['./src/styles/custom.css'],
      editLink: {
        baseUrl: 'https://github.com/rise-deploy/oauthmux/edit/develop/docs/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/rise-deploy/oauthmux',
        },
      ],
      sidebar: [
        { label: 'Home', slug: 'index' },
        { label: 'Getting started', slug: 'getting-started' },
        {
          label: 'Concepts',
          items: [{ label: 'Operating modes', slug: 'modes' }],
        },
        {
          label: 'Guides',
          items: [{ autogenerate: { directory: 'guides' } }],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Configuration', slug: 'configuration' },
            { label: 'File provider', slug: 'reference/file-provider' },
            { label: 'AWS SSM provider', slug: 'reference/ssm-provider' },
            { label: 'Runtime and deployment', slug: 'reference/runtime' },
            { label: 'HTTP endpoints', slug: 'reference/http-endpoints' },
          ],
        },
      ],
    }),
  ],
});
