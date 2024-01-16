# Branching Strategy

This document describes our branching strategy, which is based on [git flow](https://www.gitkraken.com/learn/git/git-flow).

## Documentation

We try to keep our branching strategy as simple and therefore use the following branches:

* `main`
* `dev`
* `feature`
* `release`
* `bugfix`

Hotfix or Security releases are performed outside our regular schedule depending on their severity. They are based against `bugfix`.

## Release schedule

* Minor: Monthly. On the first Tuesday of the month.
* Bugfix: Weekly. Every Tuesday.
