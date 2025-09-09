import { defineConfig } from 'vocs'

export default defineConfig({
  title: 'Tempo',
  sidebar: {
      '/issuers/': [
          { 
              text: 'Issue your own stablecoin', 
              items: [
                  {text: 'Create a TIP20 token', link: '/issuers/create-a-tip20-token' }
              ]
          },
      ],
      '/participate/': [
          {
              text: 'Participate in the Tempo network',
              items: [
                  { text: 'Run a Tempo node', link: '/participate/running-a-node' },
              ]
          }
      ],
  },
  topNav: [
      {text: 'Issuers', link: '/issuers/create-a-tip20-token'},
      {text: 'Operators', link: '/participate/running-a-node'},
  ]
})
