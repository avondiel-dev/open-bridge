"""The secrets broker: resolve a reference, run a command with it, never print it.

The skill is a package rooted at `skills/secrets/`, like the workload skill, and
it imports nothing from the repository around it. That is deliberate: the tree
can be copied out on its own and still work, and a test run happens in a scratch
copy of exactly this directory.
"""
