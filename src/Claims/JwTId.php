<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Claims;

class JwTId extends Claim
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'jti';
}
