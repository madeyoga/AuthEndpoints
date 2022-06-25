# Contributing

All contributions are welcome: use-cases, documentation, code, patches, bug reports, feature requests, etc. You do not need to be a programmer to speak up!

## Documentation

We use [docfx](https://github.com/dotnet/docfx) to generate documentations.
The docfx project can be found under [Documentation/](https://github.com/madeyoga/AuthEndpoints/tree/main/Documentation).
You can contribute to Documentation by either opening an issue or sending a pull request, then set the Issue/PR type to "documentation".

## Report a bug

To report a bug you should [open an issue](https://github.com/madeyoga/AuthEndpoints/issues) that summarizes the bug. Set the Issue type to "bug".

In order to help us understand and fix the bug it would be great if you could provide us with:

1. The steps to reproduce the bug. This includes information about e.g. the AuthEndpoints version you were using.
2. The expected behavior.
3. The actual, incorrect behavior.

Feel free to search the issue queue for existing issues that already describe the problem; if there is such issue, please add your information as a comment.

**If you want to provide a pull along with your bug report:**

That is great! In this case please send us a pull request as described in section _Create a pull request_ below.


## Contribute code

_If you are interested in contributing code to this repository but do not know where to begin:_

In this case you can [browse open issues](https://github.com/madeyoga/AuthEndpoints/issues?q=is%3Aissue+is%3Aopen). The [up-for-grabs](https://github.com/madeyoga/AuthEndpoints/labels/up-for-grabs) label is a great place to start as well.

If you are contributing C# code, it must adhere to [C# Coding Conventions](https://docs.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions).

* For _small patches_, feel free to submit pull requests directly for those patches.
* For _larger code contributions_, please use the following process. The idea behind this process is to prevent any wasted work and catch design issues early on.

    1. [Open an issue](https://github.com/madeyoga/AuthEndpoints/issues) and assign it the label of "new-feature" or "improvement", if a similar issue does not exist already. If a similar issue does exist, then you may consider participating in the work on the existing issue.
    2. Comment on the issue with your plan for implementing the issue. Explain what pieces of the codebase you are going to touch and how everything is going to fit together.
    3. AuthEndpoints committers will work with you on the design to make sure you are on the right track.
    4. Implement your issue, create a pull request (see below), and iterate from there.


## Create a pull request

Take a look at [Creating a pull request](https://help.github.com/articles/creating-a-pull-request). In a nutshell you
need to:

1. [Fork](https://help.github.com/articles/fork-a-repo) this repository.
2. Commit any changes to your fork.
3. Send a [pull request](https://help.github.com/articles/creating-a-pull-request) to this repository that you forked at step 1. 
If your pull request is related to an existing issue -- for instance, because you reported a bug/issue earlier -- 
then prefix the title of your pull request with the corresponding issue number (e.g. `123: ...`).

You may want to read [Syncing a fork](https://help.github.com/articles/syncing-a-fork) for instructions on how to keep your fork up to date with the latest changes of the upstream of this repository.

Community members who have push/merge permissions on a repository should **never** push directly to a repo, nor merge their own pull requests. 
