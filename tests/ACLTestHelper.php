<?php

namespace Mobiup\Auth\Permission\Tests;

use Mobiup\Auth\Permission\ACL;

class ACLTestHelper
{
    public static function checkIfHasCreatePermissionInOrders(ACL $acl)
    {
        return $acl->isAllowed('Mobiup\\Order', 'create');
    }
    public static function checkIfHasDeletePermissionInOrders(ACL $acl)
    {
        return $acl->isAllowed('Mobiup\\Order', 'delete');
    }
    public static function generateRandomHexadecimal($length = 16)
    {
        return bin2hex(random_bytes($length));
    }
}
