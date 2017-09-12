Note the following options.

#### Secret Key - `secret`

The key that will be used to sign your tokens. I decided to keep this separate from the Laravel `APP_KEY`
so that developers can change them independently from each other.

There is a helper artisan command to generate a random key for you, (see [Installation](https://github.com/tymondesigns/jwt-auth/wiki/Installation))

#### Token time to live - `ttl`

This is the length of time, in minutes, that your token will be considered valid. It is recommended that this is
kept as short as possible, especially if utilising token refreshing.

#### Refresh time to live - `refresh_ttl`

This is the length of time, in minutes, that you can refresh a token within. For example, if you set this to 2 weeks,
then you will only be able to refresh the same chain of tokens for a maximum of 2 weeks before the token will be
'un-refreshable' and the result will always be a `TokenExpiredException`. So after this time has passed, a brand new token
must be generated, and usually that means the user has to login again.

#### Hashing algorithm - `algo`

This is the algorithm used to *sign* the tokens. Feel free to leave this as default.

#### User model path - `user`

This should be the namespace path that points to your User class.

#### User identifier - `identifier`

This is used for retreiving the user from the token subject claim.

#### Required claims - `required_claims`

These claims must be present in the token payload or a `TokenInvalidException` will be thrown.

#### Blacklist enabled - `blacklist_enabled`

If this option is set to false, then you will not be able to invalidate tokens. Although, you
may still refresh tokens - the previous token will not be invalidated, so this is not the most
secure option. Very simple implementations may not need the extra overhead, so that is why it is
configurable.

#### Providers

These are the concrete implementations that the package will use to achieve various tasks.
You can override these, as long as the implementation adheres to the relevant interfaces.

##### User - `providers.user`

Specify the implementation that is used to find the user based on the subject claim.

##### JWT - `providers.jwt`

This will do the heavy lifting of encoding and decoding of the tokens.

##### Authentication - `providers.auth`

This will retrieve the authenticated user, via credentials or by an id.

##### Storage - `providers.storage`

This is used to drive the Blacklist, and store the tokens until they expire.