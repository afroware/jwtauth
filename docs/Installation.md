To install this package you will need:

- Laravel 4 or 5 *(see compatibility table)*
- PHP 5.4 +

Install via composer - edit your `composer.json` to require the package.

```js
"require": {
    "tymon/jwt-auth": "0.5.*"
}
```

Then run `composer update` in your terminal to pull it in.

Once this has finished, you will need to add the service provider to the `providers` array in your `app.php` config as follows:

```php
'Tymon\JWTAuth\Providers\JWTAuthServiceProvider'
```

Next, also in the `app.php` config file, under the `aliases` array, you may want to add the `JWTAuth` facade.

```php
'JWTAuth' => 'Tymon\JWTAuth\Facades\JWTAuth'
```

Also included is a Facade for the PayloadFactory. This gives you finer control over the payloads you create if you require it

```php
'JWTFactory' => 'Tymon\JWTAuth\Facades\JWTFactory'
```

Finally, you will want to publish the config using the following command:

#### Laravel 4:
```bash
$ php artisan config:publish tymon/jwt-auth
```

#### Laravel 5:
```bash
$ php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"
```

##### **Don't forget to set a secret key in the config file!**

I have included a helper command to generate a key as follows:

```bash
$ php artisan jwt:generate
```

this will generate a new random key, which will be used to sign your tokens.

And you're done!