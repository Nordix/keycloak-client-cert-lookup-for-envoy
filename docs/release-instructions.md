# Release instructions

This document describes the steps to create a new release of the project.

### Tag the release in git

Check that you have the `main` branch up to date with the remote repository:

```console
git checkout main
git pull
```

Make sure that the working directory is clean:

```console
git status
```

Update the release version in `pom.xml`, for example:

```console
mvn versions:set -DnewVersion=1.0.0
```

Run the tests to make sure that everything is working:

```console
./mvnw clean verify
```

Commit the version change:

```console
git add pom.xml && git commit -sm "Release v1.0.0"
```


Create a new tag:

```console
git tag v1.0.0
```

Update the release version in `pom.xml` to the next snapshot version, for example:

```console
mvn versions:set -DnewVersion=1.1.0-SNAPSHOT
```

Commit the version change:

```console
git add pom.xml && git commit -sm "Updated for next snapshot version"
```

Push the changes to the remote repository:

```console
git push && git push --tags
```

## Create release notes on GitHub

Go to https://github.com/Nordix/keycloak-client-cert-lookup-for-envoy/releases and click "Draft a new release".

1. Click "Choose a tag" and choose the tag that was pushed, for example `v1.0.0`.
2. Add a title, for example "v1.0.0".
3. Click "Generate release notes" to get the commit/change link.
4. Update the release notes.
5. Click "Publish release"
