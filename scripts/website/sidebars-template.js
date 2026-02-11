module.exports = {
  docs: [
    {
      type: 'category',
      label: 'Introduction',
      collapsed: true,
      items: [
        'intro',
      ]
    },
    {
      type: 'category',
      label: 'Validation',
      collapsed: true,
      items: [
        {
          type: 'category',
          label: 'General',
          collapsed: true,
          items: [
%GENERAL_ITEMS%
          ],
        },
        {
          type: 'category',
          label: 'Pod Security Standards',
          collapsed: true,
          items: [
            'pspintro',
            {
              type: 'category',
              label: 'Profiles',
              collapsed: true,
              items: [
                {
                  type: 'category',
                  label: 'Baseline',
                  collapsed: true,
                  items: [
%BASELINE_ITEMS%
                  ],
                },
                {
                  type: 'category',
                  label: 'Restricted',
                  collapsed: true,
                  items: [
%RESTRICTED_ITEMS%
                  ],
                },
              ],
            },
            {
              type: 'category',
              label: 'Other',
              collapsed: true,
              items: [
%OTHER_PSP_ITEMS%
              ],
            },
          ],
        },
      ]
    },
    {
      type: 'category',
      label: 'Mutation',
      collapsed: true,
      items: [
%MUTATION_ITEMS%
      ]
    },
  ],
};
