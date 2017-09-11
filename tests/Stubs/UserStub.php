<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Test\Stubs;

use Afroware\JwTauth\Contracts\JwTSubject;

class UserStub implements JwTSubject
{
    public function getJwTIdentifier()
    {
        return 1;
    }

    public function getJwTCustomClaims()
    {
        return [
            'foo' => 'bar',
            'role' => 'admin',
        ];
    }
}
