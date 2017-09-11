<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Test;

use Mockery;
use stdClass;
use Afroware\JwTauth\Token;
use Afroware\JwTauth\Factory;
use Afroware\JwTauth\JwTauth;
use Afroware\JwTauth\Manager;
use Afroware\JwTauth\Payload;
use Illuminate\Http\Request;
use Afroware\JwTauth\Http\Parser\Parser;
use Afroware\JwTauth\Test\Stubs\UserStub;
use Afroware\JwTauth\Exceptions\JwTException;
use Afroware\JwTauth\Contracts\Providers\Auth;
use Afroware\JwTauth\Exceptions\TokenInvalidException;

class JwTAuthTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Afroware\JwTauth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface|\Afroware\JwTauth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * @var \Mockery\MockInterface|\Afroware\JwTauth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * @var \Afroware\JwTauth\JwTauth
     */
    protected $jwTAuth;

    public function setUp()
    {
        $this->manager = Mockery::mock(Manager::class);
        $this->auth = Mockery::mock(Auth::class);
        $this->parser = Mockery::mock(Parser::class);
        $this->jwTAuth = new JwTauth($this->manager, $this->auth, $this->parser);
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));

        $this->manager
             ->shouldReceive('getPayloadFactory->customClaims')
             ->once()
             ->with(['sub' => 1, 'prv' => sha1('Afroware\JwTauth\Test\Stubs\UserStub'), 'foo' => 'bar', 'role' => 'admin'])
             ->andReturn($payloadFactory);

        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $token = $this->jwTAuth->fromUser(new UserStub);

        $this->assertSame($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_pass_provider_check_if_hash_matches()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));
        $payloadFactory->shouldReceive('get')
                       ->with('prv')
                       ->andReturn(sha1('Afroware\JwTauth\Test\Stubs\UserStub'));

        $this->manager->shouldReceive('decode')->once()->andReturn($payloadFactory);

        $this->assertTrue($this->jwTAuth->setToken('foo.bar.baz')->checkProvider('Afroware\JwTauth\Test\Stubs\UserStub'));
    }

    /** @test */
    public function it_should_pass_provider_check_if_hash_matches_when_provider_is_null()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));
        $payloadFactory->shouldReceive('get')
                       ->with('prv')
                       ->andReturnNull();

        $this->manager->shouldReceive('decode')->once()->andReturn($payloadFactory);

        $this->assertTrue($this->jwTAuth->setToken('foo.bar.baz')->checkProvider('Afroware\JwTauth\Test\Stubs\UserStub'));
    }

    /** @test */
    public function it_should_not_pass_provider_check_if_hash_not_match()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));
        $payloadFactory->shouldReceive('get')
                       ->with('prv')
                       ->andReturn(sha1('Afroware\JwTauth\Test\Stubs\UserStub1'));

        $this->manager->shouldReceive('decode')->once()->andReturn($payloadFactory);

        $this->assertFalse($this->jwTAuth->setToken('foo.bar.baz')->checkProvider('Afroware\JwTauth\Test\Stubs\UserStub'));
    }

    /** @test */
    public function it_should_return_a_token_when_passing_valid_credentials_to_attempt_method()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));

        $this->manager
             ->shouldReceive('getPayloadFactory->customClaims')
             ->once()
             ->with(['sub' => 1, 'prv' => sha1('Afroware\JwTauth\Test\Stubs\UserStub'), 'foo' => 'bar', 'role' => 'admin'])
             ->andReturn($payloadFactory);

        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $this->auth->shouldReceive('byCredentials')->once()->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn(new UserStub);

        $token = $this->jwTAuth->attempt(['foo' => 'bar']);

        $this->assertSame($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_return_false_when_passing_invalid_credentials_to_attempt_method()
    {
        $this->manager->shouldReceive('encode->get')->never();
        $this->auth->shouldReceive('byCredentials')->once()->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $token = $this->jwTAuth->attempt(['foo' => 'bar']);

        $this->assertFalse($token);
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\JwTException
     * @expectedExceptionMessage A token is required
     */
    public function it_should_throw_an_exception_when_not_providing_a_token()
    {
        $this->jwTAuth->toUser();
    }

    /** @test */
    public function it_should_return_the_owning_user_from_a_token_containing_an_existing_user()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);

        $user = $this->jwTAuth->setToken('foo.bar.baz')->customClaims(['foo' => 'bar'])->authenticate();

        $this->assertSame($user->id, 1);
    }

    /** @test */
    public function it_should_return_false_when_passing_a_token_not_containing_an_existing_user()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $user = $this->jwTAuth->setToken('foo.bar.baz')->authenticate();

        $this->assertFalse($user);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $newToken = Mockery::mock(Token::class);
        $newToken->shouldReceive('get')->once()->andReturn('baz.bar.foo');

        $this->manager->shouldReceive('customClaims->refresh')->once()->andReturn($newToken);

        $result = $this->jwTAuth->setToken('foo.bar.baz')->refresh();

        $this->assertSame($result, 'baz.bar.foo');
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, false)->andReturn(true);

        $this->jwTAuth->setToken($token)->invalidate();
    }

    /** @test */
    public function it_should_force_invalidate_a_token_forever()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, true)->andReturn(true);

        $this->jwTAuth->setToken($token)->invalidate(true);
    }

    /** @test */
    public function it_should_retrieve_the_token_from_the_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');

        $this->assertInstanceOf(Token::class, $this->jwTAuth->parseToken()->getToken());
        $this->assertEquals($this->jwTAuth->getToken(), 'foo.bar.baz');
    }

    /** @test */
    public function it_should_get_the_authenticated_user()
    {
        $manager = $this->jwTAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_return_false_if_the_token_is_invalid()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andThrow(new TokenInvalidException);

        $this->assertFalse($this->jwTAuth->parseToken()->check());
    }

    /** @test */
    public function it_should_return_true_if_the_token_is_valid()
    {
        $payload = Mockery::mock(Payload::class);

        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertTrue($this->jwTAuth->parseToken()->check());
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\JwTException
     * @expectedExceptionMessage The token could not be parsed from the request
     */
    public function it_should_throw_an_exception_when_token_not_present_in_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->jwTAuth->parseToken();
    }

    /** @test */
    public function it_should_return_false_when_no_token_is_set()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->assertFalse($this->jwTAuth->getToken());
    }

    /** @test */
    public function it_should_magically_call_the_manager()
    {
        $this->manager->shouldReceive('getBlacklist')->andReturn(new stdClass);

        $blacklist = $this->jwTAuth->manager()->getBlacklist();

        $this->assertInstanceOf(stdClass::class, $blacklist);
    }

    /** @test */
    public function it_should_set_the_request()
    {
        $request = Request::create('/foo', 'GET', ['token' => 'some.random.token']);

        $this->parser->shouldReceive('setRequest')->once()->with($request);
        $this->parser->shouldReceive('parseToken')->andReturn('some.random.token');

        $token = $this->jwTAuth->setRequest($request)->getToken();

        $this->assertEquals('some.random.token', $token);
    }

    /** @test */
    public function it_should_unset_the_token()
    {
        $this->parser->shouldReceive('parseToken')->andThrow(new JwTException);
        $token = new Token('foo.bar.baz');
        $this->jwTAuth->setToken($token);

        $this->assertSame($this->jwTAuth->getToken(), $token);
        $this->jwTAuth->unsetToken();
        $this->assertFalse($this->jwTAuth->getToken());
    }

    /** @test */
    public function it_should_get_the_manager_instance()
    {
        $manager = $this->jwTAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_get_the_parser_instance()
    {
        $parser = $this->jwTAuth->parser();
        $this->assertInstanceOf(Parser::class, $parser);
    }

    /** @test */
    public function it_should_get_a_claim_value()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertSame($this->jwTAuth->setToken('foo.bar.baz')->getClaim('sub'), 1);
    }
}
