<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Providers;

use Afroware\JwTauth\JwT;
use Afroware\JwTauth\Factory;
use Afroware\JwTauth\JwTauth;
use Afroware\JwTauth\Manager;
use Afroware\JwTauth\JwTGuard;
use Afroware\JwTauth\Blacklist;
use Afroware\JwTauth\Http\Parser\Parser;
use Afroware\JwTauth\Http\Parser\Cookies;
use Illuminate\Support\ServiceProvider;
use Afroware\JwTauth\Http\Middleware\Check;
use Afroware\JwTauth\Http\Parser\AuthHeaders;
use Afroware\JwTauth\Http\Parser\InputSource;
use Afroware\JwTauth\Http\Parser\QueryString;
use Afroware\JwTauth\Http\Parser\RouteParams;
use Afroware\JwTauth\Contracts\Providers\Auth;
use Afroware\JwTauth\Contracts\Providers\Storage;
use Afroware\JwTauth\Validators\PayloadValidator;
use Afroware\JwTauth\Http\Middleware\Authenticate;
use Afroware\JwTauth\Http\Middleware\RefreshToken;
use Afroware\JwTauth\Claims\Factory as ClaimFactory;
use Afroware\JwTauth\Console\JwTGenerateSecretCommand;
use Afroware\JwTauth\Http\Middleware\AuthenticateAndRenew;
use Afroware\JwTauth\Contracts\Providers\JwT as JwTContract;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * The middleware aliases.
     *
     * @var array
     */
    protected $middlewareAliases = [
        'jwT.auth' => Authenticate::class,
        'jwT.check' => Check::class,
        'jwT.refresh' => RefreshToken::class,
        'jwT.renew' => AuthenticateAndRenew::class,
    ];

    /**
     * Boot the service provider.
     *
     * @return void
     */
    abstract public function boot();

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJwTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJwTBlacklist();

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJwT();
        $this->registerJwTAuth();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();
        $this->registerJwTCommand();

        $this->commands('afroware.jwT.secret');
    }

    /**
     * Extend Laravel's Auth.
     *
     * @return void
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('jwT', function ($app, $name, array $config) {
            $guard = new JwTGuard(
                $app['afroware.jwT'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->alias('afroware.jwT', JwT::class);
        $this->app->alias('afroware.jwT.auth', JwTauth::class);
        $this->app->alias('afroware.jwT.provider.jwT', JwTContract::class);
        $this->app->alias('afroware.jwT.provider.auth', Auth::class);
        $this->app->alias('afroware.jwT.provider.storage', Storage::class);
        $this->app->alias('afroware.jwT.manager', Manager::class);
        $this->app->alias('afroware.jwT.blacklist', Blacklist::class);
        $this->app->alias('afroware.jwT.payload.factory', Factory::class);
        $this->app->alias('afroware.jwT.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     *
     * @return void
     */
    protected function registerJwTProvider()
    {
        $this->app->singleton('afroware.jwT.provider.jwT', function ($app) {
            $provider = $this->config('providers.jwT');

            return new $provider(
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Auth provider.
     *
     * @return void
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('afroware.jwT.provider.auth', function () {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider.
     *
     * @return void
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('afroware.jwT.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JwT Manager.
     *
     * @return void
     */
    protected function registerManager()
    {
        $this->app->singleton('afroware.jwT.manager', function ($app) {
            $instance = new Manager(
                $app['afroware.jwT.provider.jwT'],
                $app['afroware.jwT.blacklist'],
                $app['afroware.jwT.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'))
                            ->setPersistentClaims($this->config('persistent_claims'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     *
     * @return void
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('afroware.jwT.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders,
                    new QueryString,
                    new InputSource,
                    new RouteParams,
                    new Cookies,
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JwT class.
     *
     * @return void
     */
    protected function registerJwT()
    {
        $this->app->singleton('afroware.jwT', function ($app) {
            return new JwT(
                $app['afroware.jwT.manager'],
                $app['afroware.jwT.parser']
            );
        });
    }

    /**
     * Register the bindings for the main JwTauth class.
     *
     * @return void
     */
    protected function registerJwTAuth()
    {
        $this->app->singleton('afroware.jwT.auth', function ($app) {
            return new JwTauth(
                $app['afroware.jwT.manager'],
                $app['afroware.jwT.provider.auth'],
                $app['afroware.jwT.parser']
            );
        });
    }

    /**
     * Register the bindings for the Blacklist.
     *
     * @return void
     */
    protected function registerJwTBlacklist()
    {
        $this->app->singleton('afroware.jwT.blacklist', function ($app) {
            $instance = new Blacklist($app['afroware.jwT.provider.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'))
                            ->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     *
     * @return void
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('afroware.jwT.validators.payload', function () {
            return (new PayloadValidator)
                ->setRefreshTTL($this->config('refresh_ttl'))
                ->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Claim Factory.
     *
     * @return void
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('afroware.jwT.claim.factory', function ($app) {
            $factory = new ClaimFactory($app['request']);
            $app->refresh('request', $factory, 'setRequest');

            return $factory->setTTL($this->config('ttl'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     *
     * @return void
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('afroware.jwT.payload.factory', function ($app) {
            return new Factory(
                $app['afroware.jwT.claim.factory'],
                $app['afroware.jwT.validators.payload']
            );
        });
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerJwTCommand()
    {
        $this->app->singleton('afroware.jwT.secret', function () {
            return new JwTGenerateSecretCommand;
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  string  $key
     * @param  string  $default
     *
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("jwT.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param  string  $key
     *
     * @return mixed
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
