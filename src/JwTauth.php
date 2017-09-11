<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth;

use Afroware\JwTauth\Http\Parser\Parser;
use Afroware\JwTauth\Contracts\Providers\Auth;

class JwTauth extends JwT
{
    /**
     * The authentication provider.
     *
     * @var \Afroware\JwTauth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * Constructor.
     *
     * @param  \Afroware\JwTauth\Manager  $manager
     * @param  \Afroware\JwTauth\Contracts\Providers\Auth  $auth
     * @param  \Afroware\JwTauth\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(Manager $manager, Auth $auth, Parser $parser)
    {
        parent::__construct($manager, $parser);
        $this->auth = $auth;
    }

    /**
     * Attempt to authenticate the user and return the token.
     *
     * @param  array  $credentials
     *
     * @return false|string
     */
    public function attempt(array $credentials)
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->user());
    }

    /**
     * Authenticate a user via a token.
     *
     * @return \Afroware\JwTauth\Contracts\JwTSubject|false
     */
    public function authenticate()
    {
        $id = $this->getPayload()->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->user();
    }

    /**
     * Alias for authenticate().
     *
     * @return \Afroware\JwTauth\Contracts\JwTSubject|false
     */
    public function toUser()
    {
        return $this->authenticate();
    }

    /**
     * Get the authenticated user.
     *
     * @return \Afroware\JwTauth\Contracts\JwTSubject
     */
    public function user()
    {
        return $this->auth->user();
    }
}
