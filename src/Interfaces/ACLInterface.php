<?php

namespace Mobiup\Auth\Permission\Interfaces;

interface ACLInterface
{
    /**
     * ACL constructor.
     * @param array|string $acl
     */
    public function __construct($acl);

    // PHP 8
    //public function __construct(array|string $acl);

    /**
     * @return bool
     */
    public function isAllowed() : bool;

    /**
     * @return array|bool|string
     */
    public function getAllowance();

    // PHP 8
    //public function getAllowance() : array|bool|string;

    /**
     * @param false $asJson
     * @return array|false|string
     */
    public function export($asJson = false);
}
