"""The object-store resolver: object://<store>/<key> to a path, never to content.

The package is named `objstore`, not `engine`, because the secrets skill's
package is `engine` and this one imports it in-process to resolve credentials.
Two packages with one name in one process is an import that works on the
machine that wrote it and picks the wrong module on the next.
"""
