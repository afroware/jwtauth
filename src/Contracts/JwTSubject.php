<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Contracts;

interface JwTSubject
{
    /**
     * Get the identifier that will be stored in the subject claim of the JwT.
     *
     * @return mixed
     */
    public function getJwTIdentifier();

    /**
     * Return a key value array, containing any custom claims to be added to the JwT.
     *
     * @return array
     */
    public function getJwTCustomClaims();
}
