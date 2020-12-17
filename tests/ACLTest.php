<?php
/**
 * (c) 2020 Mobiup - www.mobiup.com.br
 * @license MIT
 */

namespace Mobiup\Auth\Permission\Tests;

use InvalidArgumentException;
use Mobiup\Auth\Permission\ACL;
use PHPUnit\Framework\TestCase;

class ACLTest extends TestCase
{
    public function testConstructorAndExport()
    {
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

        // As array
        $aclArray = new ACL($rules);
        $this->assertTrue(ACLTestHelper::checkIfHasCreatePermissionInOrders($aclArray));
        $this->assertFalse(ACLTestHelper::checkIfHasDeletePermissionInOrders($aclArray));

        // As json
        $aclJson = new ACL(json_encode($rules));
        $this->assertTrue(ACLTestHelper::checkIfHasCreatePermissionInOrders($aclJson));
        $this->assertFalse(ACLTestHelper::checkIfHasDeletePermissionInOrders($aclJson));

        // Results must be the same
        $this->assertEquals($aclArray->export(true), $aclJson->export(true));
        $this->assertEquals($aclArray->export(), $aclJson->export());
    }

    public function testAllAllowed()
    {
        $rules = [
            '*',
        ];

        // As array
        $acl = new ACL($rules);
        $this->assertTrue($acl->isAllowed(
            ACLTestHelper::generateRandomHexadecimal(),
            ACLTestHelper::generateRandomHexadecimal(),
            ACLTestHelper::generateRandomHexadecimal(),
            ACLTestHelper::generateRandomHexadecimal()
        ));
    }

    public function testArrayArguments()
    {
        $rules = [
            'Mobiup\\Customer' => [
                'read',
                'create',
                'update',
            ],
        ];

        // As array
        $acl = new ACL($rules);

        // Not expecting to have permission for random stuff
        $this->assertFalse($acl->isAllowed([
            'Mobiup\\Customer',
            ACLTestHelper::generateRandomHexadecimal(),
            ACLTestHelper::generateRandomHexadecimal(),
            ACLTestHelper::generateRandomHexadecimal(),
        ]));

        $this->assertTrue($acl->isAllowed([
            'Mobiup\\Customer',
            'read',
        ]));

        $this->assertFalse($acl->isAllowed([
            'Mobiup\\Customer',
            'delete',
        ]));
    }

    public function testStarCases()
    {
        $rules = [
            'Mobiup\\Order' => [
                'read' => [
                    'channel' => [
                        'cha1',
                        'cha2',
                    ],
                ],
            ],
        ];

        // As array
        $acl = new ACL($rules);
        $this->assertFalse($acl->isAllowed([
            'Mobiup\\Order',
            'read',
            'channel',
            'cha3',
        ]));

        $rules = [
            'Mobiup\\Order' => [
                'read' => [
                    'channel' => '*',
                ],
            ],
        ];

        // As array
        $acl = new ACL($rules);
        $this->assertTrue($acl->isAllowed([
            'Mobiup\\Order',
            'read',
            'channel',
            'cha3',
        ]));
        $this->assertFalse($acl->isAllowed([
            'Mobiup\\Order',
            'create',
            'channel',
            'cha3',
        ]));

        $rules = [
            'Mobiup\\Order' => [
                '*' => [
                    'channel' => [
                        'cha1',
                        'cha2',
                    ],
                ],
            ],
        ];

        // As array
        $acl = new ACL($rules);
        $this->assertFalse($acl->isAllowed([
            'Mobiup\\Order',
            'read',
            'channel',
            'cha3',
        ]));
        $this->assertTrue($acl->isAllowed([
            'Mobiup\\Order',
            'create',
            'channel',
            'cha2',
        ]));

        $rules = [
            'Mobiup\\Order' => [
                '*' => [
                    'channel' => [
                        'cha1',
                        'cha2',
                    ],
                ],
                'read' => [
                    'channel' => [
                        'cha1',
                    ],
                ],
            ],
        ];

        // As array
        $acl = new ACL($rules);
        $this->assertFalse($acl->isAllowed([
            'Mobiup\\Order',
            'read',
            'channel',
            'cha3',
        ]));
        $this->assertTrue($acl->isAllowed([
            'Mobiup\\Order',
            'create',
            'channel',
            'cha2',
        ]));
        $this->assertTrue($acl->isAllowed([
            'Mobiup\\Order',
            'read',
            'channel',
            'cha1',
        ]));
        $this->assertFalse($acl->isAllowed([
            'Mobiup\\Order',
            'read',
            'channel',
            'cha2',
        ]));
    }

    public function testPermissionWithoutChildrenInTheSameLevelOfPermissionWithChildren()
    {
        $rules = [
            'Mobiup\\Order' => [
                'read' => [
                    'channel' => [
                        'cha1',
                        'cha2' => '*',
                        'cha3' => [
                            'foo',
                            'bar',
                        ],
                    ],
                ],
            ],
        ];

        // As array
        $acl = new ACL($rules);
        $this->assertTrue($acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha1'));
        $this->assertFalse($acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha1', 'any', 'any'));
        $this->assertTrue($acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha2', 'any', 'any'));
        $this->assertFalse($acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha3'));
        $this->assertFalse($acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha3', 'any'));
        $this->assertTrue($acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha3', 'foo'));
        $this->assertFalse($acl->isAllowed('Mobiup\\Order', 'read', 'channel', 'cha3', 'foo', 'any'));
    }

    public function testGetAllowance()
    {
        $rules = [
            'Mobiup\\Order' => [
                'read' => [
                    'channel' => [
                        'cha1',
                        'cha2',
                        'cha3',
                        'cha4',
                        'cha5' => '*',
                        'cha6' => [
                            'foo',
                            'bar',
                        ],
                    ],
                ],
            ],
        ];

        // As array
        $acl = new ACL($rules);
        $this->assertEquals('*', $acl->getAllowance('Mobiup\\Order', 'read', 'channel', 'cha2'));
        $this->assertEquals('*', $acl->getAllowance('Mobiup\\Order', 'read', 'channel', 'cha5'));
        $this->assertFalse($acl->getAllowance('Mobiup\\Order', 'read'));
        $this->assertFalse($acl->getAllowance('Mobiup\\Order', 'read', 'any'));
        $this->assertIsArray($acl->getAllowance('Mobiup\\Order', 'read', 'channel', 'cha6'));
        $this->assertEquals('*', $acl->getAllowance('Mobiup\\Order', 'read', 'channel', 'cha6', 'foo'));
    }

    public function testConstructorException()
    {
        $this->expectException(InvalidArgumentException::class);

        new ACL('======');
    }
}
