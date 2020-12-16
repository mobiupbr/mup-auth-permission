<?php
/**
 * (c) 2020 Mobiup - www.mobiup.com.br
 * @license MIT
 */

namespace Mobiup\Auth\Permission;

use InvalidArgumentException as InvalidArgumentExceptionAlias;

/**
 * Class ACL
 * @package Mobiup\Auth\Permission
 */
class ACL
{
    private array $acl = [];

    /**
     * ACL constructor.
     * @param $acl
     */
    public function __construct($acl)
    {
        if (!is_array($acl)) {
            // Expects json when is not array
            $acl = json_decode($acl, true);

            if ($acl === null) {
                throw new InvalidArgumentExceptionAlias('ACL construct expects an array or json.');
            }
        }

        $this->acl = $acl;
    }

    /**
     * @return bool
     */
    public function isAllowed()
    {
        $permissions = func_get_args();

        if (is_array($permissions[0])) {
            $permissions = $permissions[0];
        }

        return $this->verifyPermission($permissions);
    }

    /**
     * @param $permissions
     * @param null $acl
     * @return bool
     */
    private function verifyPermission($permissions, $acl = null)
    {
        if ($acl === null) {
            $acl = $this->acl;
        }

        foreach ($permissions as $key => $permission) {
            // Remove value that is been processed
            unset($permissions[$key]);

            $permissionLabelExists = array_key_exists($permission, $acl);

            if (!$permissionLabelExists) {
                if (array_key_exists('*', $acl)) {
                    $permission = '*';
                    $permissionLabelExists = true;
                }
            }

            if ($permissionLabelExists) {
                if (is_array($acl[$permission])) {
                    return $this->verifyPermission($permissions, $acl[$permission]);
                }

                if ($acl[$permission] === '*') {
                    return true;
                }
            }

            if (array_key_exists('*', $acl)) {
                if (is_array($acl[$permission] )) {
                    return $this->verifyPermission($permissions, $acl[$permission]);
                }

                if ($acl[$permission] === '*') {
                    return true;
                }
            }

            foreach ($acl as $subKey => $value) {
                if (is_int($subKey) && ($value === $permission || $value === '*')) {
                    return true;
                }
            }

            // When no permission was found
            return false;
        }

        // When is requesting permission that is not the final level
        return false;
    }
}