There are several ways to create a token within the package. There are simple ways to do it, and more advanced methods if you want greater control.

Out of the box there are a number of required claims, Although this can be configured:

`sub` **Subject** - This holds the identifier for the token (defaults to user id)

`iat` **Issued At** - When the token was issued (unix timestamp)

`exp` **Expiry** - The token expiry date (unix timestamp)

`nbf` **Not Before** - The earliest point in time that the token can be used (unix timestamp)

`iss` **Issuer** - The issuer of the token (defaults to the request url)

`jti` **JWT Id** - A unique identifier for the token (md5 of the sub and iat claims)

`aud` **Audience** - The intended audience for the token (not required by default)

Custom claims are also allowed. More on that later.

## Creating a Token based on the users credentials
The most common way to create a token would be to authenticate the user via their login credentials, and if successful return a token corresponding to that user. For example, let's say we have a Laravel `AuthenticateController`

#### Laravel 5

```php
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthenticateController extends Controller
{
    public function authenticate(Request $request)
    {
        // grab credentials from the request
        $credentials = $request->only('email', 'password');

        try {
            // attempt to verify the credentials and create a token for the user
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        // all good so return the token
        return response()->json(compact('token'));
    }
}
```

#### Laravel 4

```php
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthenticateController extends Controller
{
    public function authenticate()
    {
        // grab credentials from the request
        $credentials = Input::only('email', 'password');

        try {
            // attempt to verify the credentials and create a token for the user
            if (! $token = JWTAuth::attempt($credentials)) {
                return Response::json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return Response::json(['error' => 'could_not_create_token'], 500);
        }

        // all good so return the token
        return Response::json(compact('token'));
    }
}
```

## Creating a Token based on a user object

You can also skip user authentication and just pass in a User object. e.g.

```php
// grab some user
$user = User::first();

$token = JWTAuth::fromUser($user);
```

The above two methods also have a second parameter where you can pass an array of custom claims. e.g.

```php
$customClaims = ['foo' => 'bar', 'baz' => 'bob'];

JWTAuth::attempt($credentials, $customClaims);
// or
JWTAuth::fromUser($user, $customClaims);
```

And these custom claims will be available alongside the other claims when decoding the token.

*Note:* Be wary about adding lots of custom claims as this will increase the size of your token.

## Creating a Token based on anything you like

I have provided access to the underlying classes and methods to offer advanced/custom functionality.

Example using the built in `Tymon\JWTAuth\PayloadFactory` instance (or using the included `JWTFactory` facade):
```php
$customClaims = ['foo' => 'bar', 'baz' => 'bob'];

$payload = JWTFactory::make($customClaims);

$token = JWTAuth::encode($payload);
```

You can also chain claims directly onto the `Tymon\JWTAuth\PayloadFactory` instance, (or using the included `JWTFactory` facade)

```php
// add a custom claim with a key of `foo` and a value of ['bar' => 'baz']
$payload = JWTFactory::sub(123)->aud('foo')->foo(['bar' => 'baz'])->make();

$token = JWTAuth::encode($payload);
```
