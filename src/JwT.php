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

use BadMethodCallException;
use Illuminate\Http\Request;
use Afroware\JwTauth\Http\Parser\Parser;
use Afroware\JwTauth\Contracts\JwTSubject;
use Afroware\JwTauth\Support\CustomClaims;
use Afroware\JwTauth\Exceptions\JwTException;

class JwT
{
    use CustomClaims;

    /**
     * The authentication manager.
     *
     * @var \Afroware\JwTauth\Manager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \Afroware\JwTauth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * The token.
     *
     * @var \Afroware\JwTauth\Token|null
     */
    protected $token;

    /**
     * JwT constructor.
     *
     * @param  \Afroware\JwTauth\Manager  $manager
     * @param  \Afroware\JwTauth\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     *
     * @param  \Afroware\JwTauth\Contracts\JwTSubject  $subject
     *
     * @return string
     */
    public function fromSubject(JwTSubject $subject)
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
     *
     * @param  \Afroware\JwTauth\Contracts\JwTSubject  $user
     *
     * @return string
     */
    public function fromUser(JwTSubject $user)
    {
        return $this->fromSubject($user);
    }

    /**
     * Refresh an expired token.
     *
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     *
     * @return string
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())
                             ->refresh($this->token, $forceForever, $resetClaims)
                             ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     *
     * @param  bool  $forceForever
     *
     * @return $this
     */
    public function invalidate($forceForever = false)
    {
        $this->requireToken();

        $this->manager->invalidate($this->token, $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @throws \Afroware\JwTauth\Exceptions\JwTException
     *
     * @return \Afroware\JwTauth\Payload
     */
    public function checkOrFail()
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     * @param  bool  $getPayload
     *
     * @return \Afroware\JwTauth\Payload|bool
     */
    public function check($getPayload = false)
    {
        try {
            $payload = $this->checkOrFail();
        } catch (JwTException $e) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     *
     * @return \Afroware\JwTauth\Token|false
     */
    public function getToken()
    {
        if (! $this->token) {
            try {
                $this->parseToken();
            } catch (JwTException $e) {
                return false;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @throws \Afroware\JwTauth\Exceptions\JwTException
     *
     * @return $this
     */
    public function parseToken()
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JwTException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     *
     * @return \Afroware\JwTauth\Payload
     */
    public function getPayload()
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
    }

    /**
     * Alias for getPayload().
     *
     * @return \Afroware\JwTauth\Payload
     */
    public function payload()
    {
        return $this->getPayload();
    }

    /**
     * Convenience method to get a claim value.
     *
     * @param  string  $claim
     *
     * @return mixed
     */
    public function getClaim($claim)
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     *
     * @param  \Afroware\JwTauth\Contracts\JwTSubject  $subject
     *
     * @return \Afroware\JwTauth\Payload
     */
    public function makePayload(JwTSubject $subject)
    {
        return $this->factory()->customClaims($this->getClaimsArray($subject))->make();
    }

    /**
     * Build the claims array and return it.
     *
     * @param  \Afroware\JwTauth\Contracts\JwTSubject  $subject
     *
     * @return array
     */
    protected function getClaimsArray(JwTSubject $subject)
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getJwTCustomClaims(), // custom claims from JwTSubject method
            $this->customClaims // custom claims from inline setter
        );
    }

    /**
     * Get the claims associated with a given subject.
     *
     * @param  \Afroware\JwTauth\Contracts\JwTSubject  $subject
     *
     * @return array
     */
    protected function getClaimsForSubject(JwTSubject $subject)
    {
        return [
            'sub' => $subject->getJwTIdentifier(),
            'prv' => $this->hashProvider($subject),
        ];
    }

    /**
     * Hash the provider and return it.
     *
     * @param  string|object  $provider
     *
     * @return string
     */
    protected function hashProvider($provider)
    {
        return sha1(is_object($provider) ? get_class($provider) : $provider);
    }

    /**
     * Check if the provider matches the one saved in the token.
     *
     * @param  string|object  $provider
     *
     * @return bool
     */
    public function checkProvider($provider)
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashProvider($provider) === $prv;
    }

    /**
     * Set the token.
     *
     * @param  \Afroware\JwTauth\Token|string  $token
     *
     * @return $this
     */
    public function setToken($token)
    {
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

        return $this;
    }

    /**
     * Ensure that a token is available.
     *
     * @throws \Afroware\JwTauth\Exceptions\JwTException
     *
     * @return void
     */
    protected function requireToken()
    {
        if (! $this->token) {
            throw new JwTException('A token is required');
        }
    }

    /**
     * Set the request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Get the Manager instance.
     *
     * @return \Afroware\JwTauth\Manager
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return \Afroware\JwTauth\Http\Parser\Parser
     */
    public function parser()
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     *
     * @return \Afroware\JwTauth\Factory
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     *
     * @return \Afroware\JwTauth\Blacklist
     */
    public function blacklist()
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the JwT Manager.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
