Once a user has logged in with their credentials, then the next step would be to make a subsequent request, with the token, to retrieve the users' details, so you can show them as being logged in.

To make authenticated requests via http using the built in methods, you will need to set an authorization header as follows:

```
Authorization: Bearer {yourtokenhere}
```

**_Note to Apache users_**

Apache seems to discard the Authorization header if it is not a base64 encoded user/pass combo.
So to fix this you can add the following to your apache config

```
RewriteEngine On
RewriteCond %{HTTP:Authorization} ^(.*)
RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]
```

Alternatively you can include the token via a query string

```
http://api.mysite.com/me?token={yourtokenhere}
```
To get the token from the request you can do:

```php
// this will set the token on the object
JWTAuth::parseToken();

// and you can continue to chain methods
$user = JWTAuth::parseToken()->authenticate();
```

To get the token value, you can call:

```php
$token = JWTAuth::getToken();
```
This will return the token if one is set, otherwise (as a convenience)
it will try to parse the token from the request, using the above method,
and ultimately return false, if no token is set or can be parsed.

Of course you can also manually set the token aswell, as needed if there are other entry points into your application. e.g.

```php
JWTAuth::setToken('foo.bar.baz');
```

#### Retreiving the Authenticated user from a token

```php
// somewhere in your controller
public function getAuthenticatedUser()
{
	try {

		if (! $user = JWTAuth::parseToken()->authenticate()) {
			return response()->json(['user_not_found'], 404);
		}

	} catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

		return response()->json(['token_expired'], $e->getStatusCode());

	} catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

		return response()->json(['token_invalid'], $e->getStatusCode());

	} catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

		return response()->json(['token_absent'], $e->getStatusCode());

	}

	// the token is valid and we have found the user via the sub claim
	return response()->json(compact('user'));
}
```

#### Global exception handling

If you don't like the idea of catching mulitple exceptions inline,
then you are free to add a global exception handler with Laravel.

##### Laravel 4

Add the following code to `app/start/global.php`

```php
App::error(function(Tymon\JWTAuth\Exceptions\JWTException $e, $code)
{
	if ($e instanceof Tymon\JWTAuth\Exceptions\TokenExpiredException) {
		return Response::json(['token_expired'], $e->getStatusCode());
	} else if ($e instanceof Tymon\JWTAuth\Exceptions\TokenInvalidException) {
		return Response::json(['token_invalid'], $e->getStatusCode());
	}
});
```

##### Laravel 5

Add the following code to the render method within `app/Exceptions/Handler.php`

```php
public function render($request, Exception $e)
{
	if ($e instanceof Tymon\JWTAuth\Exceptions\TokenExpiredException) {
		return response()->json(['token_expired'], $e->getStatusCode());
	} else if ($e instanceof Tymon\JWTAuth\Exceptions\TokenInvalidException) {
		return response()->json(['token_invalid'], $e->getStatusCode());
	}

	return parent::render($request, $e);
}
```

#### Middleware and Filters

##### Laravel 4

If you are using Laravel 4 (`0.4.*`) then you can use the included `jwt-auth` filter.
It includes some sensible default responses when, for example, the token has expired or is invalid.

```php
Route::post('me', ['before' => 'jwt-auth', function() {

    $user = JWTAuth::parseToken()->toUser();

    return Response::json(compact('user'));
}]);
```

These responses can be overridden, by hooking into a series of events that are fired before the response is returned. Here are the events that can be fired during the filter.

```php
// fired when the token could not be found in the request
Event::listen('tymon.jwt.absent');

// fired when the token has expired
Event::listen('tymon.jwt.expired');

// fired when the token is found to be invalid
Event::listen('tymon.jwt.invalid');

// fired if the user could not be found (shouldn't really happen)
Event::listen('tymon.jwt.user_not_found');

// fired when the token is valid (User is passed along with event)
Event::listen('tymon.jwt.valid');
```

##### Laravel 5

If using Laravel 5 (`0.5.*`) then you have access to 2 included Middlewares:

_GetUserFromToken_<br>
This will check the header and query string (as explained above) for the presence of a token, and attempts to decode it. The same events are fired, as above.

_RefreshToken_<br>
This middleware will again try to parse the token from the request, and in turn will refresh the token (thus invalidating the old one) and return it as part of the next response. This essentially yields a single use token flow, which reduces the window of attack if a token is compromised, since it is only valid for the single request.

To use the middlewares you will have to register them in `app/Http/Kernel.php` under the `$routeMiddleware` property:

```php
protected $routeMiddleware = [
	...
	'jwt.auth' => 'Tymon\JWTAuth\Middleware\GetUserFromToken',
	'jwt.refresh' => 'Tymon\JWTAuth\Middleware\RefreshToken',
];
```