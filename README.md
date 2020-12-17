# Mobiup Authentication Permission

## Installation by composer
Run `composer require mobiupbr/mup-auth-permission`.

## Examples:

        $rules = [
            'Mobiup\\Order' => [
                'read' => [
                    'channel' => [
                        'cha1',
                        'cha2',
                        'cha3' => [
                            'foo',
                            'bar',
                        ],
                    ],
                ],
                'create',
                'update',
            ],

            'Mobiup\\Customer' => [
                'read',
                'create',
                'update',
            ],
        ];

        $acl = new ACL($rules);

        $acl->isAllowed('Mobiup\\Order', 'read'); // returns false
        $acl->isAllowed('Mobiup\\Order', 'read', 'channel'); // returns false
        $acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha1'); // returns true
        $acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha4'); // returns false

        $acl->isAllowed('Mobiup\\Customer', 'read'); // returns true

        $acl->getAllowance('Mobiup\\Order', 'read'); // returns false
        $acl->getAllowance('Mobiup\\Order', 'read', 'channel'); // returns ['cha1', 'cha2']
        $acl->getAllowance('Mobiup\\Order', 'read', 'channel', 'cha3'); // returns ['foo', 'bar']