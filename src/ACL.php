<?php
/**
 * (c) 2020 Mobiup - www.mobiup.com.br
 * @license MIT
 */

namespace Mobiup\Auth\Permission;

use InvalidArgumentException;

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
                throw new InvalidArgumentException('ACL constructor expects an array or json.');
            }
        }

        $this->acl = $acl;
    }

    /**
     * @return bool
     */
    public function isAllowed() : bool
    {
        $permissions = func_get_args();

        return $this->permissionInit($permissions);
    }

    /**
     * @return array|bool|string
     */
    public function getAllowance()
    {
        $permissions = func_get_args();

        return $this->permissionInit($permissions, true);
    }

    /**
     * @param $permissions
     * @param false $getAllowance
     * @return array|bool|string
     */
    protected function permissionInit($permissions, $getAllowance = false)
    {
        if (is_array($permissions[0])) {
            $permissions = $permissions[0];
        }

        return $this->verifyPermission($permissions, $getAllowance, $this->acl);
    }

    /**
     * @param $permissions
     * @param $getAllowance
     * @param null $acl
     * @return bool|array
     */
    private function verifyPermission($permissions, $getAllowance, $acl)
    {
        foreach ($permissions as $key => $permission) {
            // Remove value that is been processed
            unset($permissions[$key]);

            // Check if exists a permission with that label
            $permissionLabelExists = array_key_exists($permission, $acl);

            if (!$permissionLabelExists) {
                // Didn't find the label, so check for a star
                if (array_key_exists('*', $acl)) {
                    // Set as if it was the label
                    $permission = '*';
                    $permissionLabelExists = true;
                }
            }

            // If found a label or star in this level
            if ($permissionLabelExists) {
                // Check if is there more levels
                if (is_array($acl[$permission])) {
                    return $this->verifyPermission($permissions, $getAllowance, $acl[$permission]);
                }

                // Return the permissions
                if ($getAllowance) {
                    return $acl[$permission];
                }

                // If it is the last level, looks for a star
                if ($acl[$permission] === '*') {
                    return true;
                }
            }

            // Check each values that can be a last level
            foreach ($acl as $subKey => $value) {
                $isIntKey = is_int($subKey);

                if (
                    // If is an int, means that is last level and need to consider the value
                    $isIntKey
                    && (
                        // Check if the value is the permission and there is no child permission asked
                        ($value === $permission && empty($permissions))
                        // Or is a star
                        || $value === '*'
                    )
                ) {
                    if ($getAllowance) {
                        return '*';
                    }

                    return true;
                }
            }

            // When no permission was found
            return false;
        }

        // Return the permissions
        if ($getAllowance) {
            $permissions = [];

            foreach ($acl as $key => $permission) {
                if (is_int($key)) {
                    $permissions[] = $permission;
                }
            }

            if (empty($permissions)) {
                return false;
            }

            return $permissions;
        }

        // When is requesting permission that is not the final level
        return false;
    }

    /**
     * @param false $asJson
     * @return array|false|mixed|string
     */
    public function export($asJson = false)
    {
        if ($asJson) {
            return json_encode($this->acl);
        }

        return $this->acl;
    }
}
