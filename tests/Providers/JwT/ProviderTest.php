<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Test\Providers\JwT;

use Afroware\JwTauth\Test\AbstractTestCase;
use Afroware\JwTauth\Test\Stubs\JwTProviderStub;

class ProviderTest extends AbstractTestCase
{
    /**
     * @var \Afroware\JwTauth\Test\Stubs\JwTProviderStub
     */
    protected $provider;

    public function setUp()
    {
        parent::setUp();

        $this->provider = new JwTProviderStub('secret', [], 'HS256');
    }

    /** @test */
    public function it_should_set_the_algo()
    {
        $this->provider->setAlgo('HS512');

        $this->assertSame('HS512', $this->provider->getAlgo());
    }

    /** @test */
    public function it_should_set_the_secret()
    {
        $this->provider->setSecret('foo');

        $this->assertSame('foo', $this->provider->getSecret());
    }
}
