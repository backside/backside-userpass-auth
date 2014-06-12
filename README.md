backside-ruletree-security
==============

This module implements a security mechanism for backside that emulates the firebase security mechanism

# Configuration
```JavaScript
new UserPassAuth(persistence, [opts])
```
Where persistence is an instance of BacksidePersistence and opts is and optional options array
with the following fields:
```
{
  logger: an instance of the logger,
  userPath: the path that users will be stored under in the private store
  saltIterations: the number of iterations of the salt
  expire: the number of seconds until the token expires
  secret: the secret to use to sign tokens
}
```
# Set secret via environemt variable
The secret used to sign tokens can be set via the environemt variable `RULE_TREE_SECRET`
