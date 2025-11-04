# How to contribute

We are really glad you're reading this, because we need volunteer developers
to help this project come to fruition.

Here are some important resources:

  * [OpenStack contribution guide](https://docs.openstack.org/contributors/index.html)
  * Bugs? [GitHub issues](https://github.com/openstack-experimental/keystone/issues)
  * IRC: chat.oftc.net channel [#openstack-keystone](https://docs.openstack.org/contributors/common/irc.html).
    We're spread across the globe, hopefully close to your TZ.

## Testing

We try to implement unit and functional testing for every piece of the
functionality. In the federation area we try to ensure that we have a
real functional tests for every available provider.

## Submitting changes

Please send a [GitHub Pull Request](https://github.com/openstack-experimental/keystone/pull/new/main)
with a clear list of what you've done (read more about
[pull requests](http://help.github.com/pull-requests/)).  Please follow our
coding conventions (below) and make sure all of your commits are atomic
(one feature per commit).

Since our target for the project is to become official OpenStack project we
would require Signed-off in the commit message sometime soon.

Always write a clear log message for your commits. One-line messages are fine
for small changes, but bigger changes should look like this:

    $ git commit -s -m "A brief summary of the commit
    >
    > A paragraph describing what changed and its impact."

## Coding conventions

Start reading our code and hopefully it is reasonable well documented. If not
than please help us

* Use "Result<." and "?" to properly propagate errors
* Pass by reference when receiver is not supposed to take ownership
* "thiserror" is used to define internal errors. Ensure that enough context
  information is available in the error.
