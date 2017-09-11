<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Test\Validators;

use Afroware\JwTauth\Claims\JwTId;
use Afroware\JwTauth\Claims\Issuer;
use Afroware\JwTauth\Claims\Subject;
use Afroware\JwTauth\Claims\IssuedAt;
use Afroware\JwTauth\Claims\NotBefore;
use Afroware\JwTauth\Claims\Collection;
use Afroware\JwTauth\Claims\Expiration;
use Afroware\JwTauth\Test\AbstractTestCase;
use Afroware\JwTauth\Validators\PayloadValidator;

class PayloadValidatorTest extends AbstractTestCase
{
    /**
     * @var \Afroware\JwTauth\Validators\PayloadValidator
     */
    protected $validator;

    public function setUp()
    {
        parent::setUp();

        $this->validator = new PayloadValidator;
    }

    /** @test */
    public function it_should_return_true_when_providing_a_valid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue($this->validator->isValid($collection));
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\TokenExpiredException
     * @expectedExceptionMessage Token has expired
     */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [nbf]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp + 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [iat]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage JwT payload does not contain the required claims
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [exp]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration('foo'),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /** @test */
    public function it_should_set_the_required_claims()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue($this->validator->setRequiredClaims(['iss', 'sub'])->isValid($collection));
    }

    /** @test */
    public function it_should_check_the_token_in_the_refresh_context()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1000),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 2600), // this is LESS than the refresh ttl at 1 hour
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(60)->isValid($collection)
        );
    }

    /** @test */
    public function it_should_return_true_if_the_refresh_ttl_is_null()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1000),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 2600), // this is LESS than the refresh ttl at 1 hour
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(null)->isValid($collection)
        );
    }

    /**
     * @test
     * @expectedException \Afroware\JwTauth\Exceptions\TokenExpiredException
     * @expectedExceptionMessage Token has expired and can no longer be refreshed
     */
    public function it_should_throw_an_exception_if_the_token_cannot_be_refreshed()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 5000), // this is MORE than the refresh ttl at 1 hour, so is invalid
            new JwTId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->setRefreshFlow()->setRefreshTTL(60)->check($collection);
    }
}
