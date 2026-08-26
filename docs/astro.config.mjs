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
        {
          label: 'Concepts',
          items: [{ label: 'Operating modes', slug: 'modes' }],
        },
        {
          label: 'Guides',
          items: [{ autogenerate: { directory: 'guides' } }],
        },
      ],
    }),
  ],
});
