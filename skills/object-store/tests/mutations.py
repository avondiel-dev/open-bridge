"""The mutation battery: proof that this suite has teeth.

Every entry names one literal inside one source, the softened version of it, and
the ONE test that has to turn red when the softening is applied. A suite that
stays green under any of these is not a suite. It reports a proof nobody ran.

The needles map onto the acceptance criteria of #226 and the decisions of
docs/object-store.md: content never in the output, three named outcomes for a
read that cannot be served, a write that never queues, a cache that says when it
answered, a directory that is never created where a volume should be mounted.

Two needles name tests/support.py rather than an engine source. The guard there
is the only thing keeping this suite off a live bucket, and in a green run it
never fires, so nothing but a needle would notice that it had stopped refusing.
"""

from __future__ import annotations

from dataclasses import dataclass

REFS = "objstore/refs.py"
ERRORS = "objstore/errors.py"
STORES = "objstore/stores.py"
CACHE = "objstore/cache.py"
CREDS = "objstore/credentials.py"
LOCAL = "objstore/backends/local.py"
S3 = "objstore/backends/s3.py"
SIGV4 = "objstore/sigv4.py"
RESOLVER = "objstore/resolver.py"
CLI = "objstore/cli.py"
SUPPORT = "tests/support.py"


@dataclass(frozen=True)
class Mutation:
    """One softening, and the test that must notice it."""

    name: str
    file: str
    search: str
    replace: str
    test: str
    scar: str


MUTATIONS = (
    # -- the grammar -------------------------------------------------------
    Mutation(
        name="a-key-may-climb-out-of-its-store",
        file=REFS, search='SEGMENT = r"(?!\\.\\.?(?:/|$))[^/\\s\\\\]+"', replace='SEGMENT = r"[^/\\s\\\\]+"',
        test="tests.test_refs.ParsingAReference.test_a_key_that_climbs_out_is_refused",
        scar="object://store/../x reaches a local backend as a path one level above the root"),
    Mutation(
        name="any-scheme-parses-as-an-object-reference",
        file=REFS, search='_prefix = "^" + SCHEME + "://"', replace='_prefix = "^[a-z0-9]+://"',
        test="tests.test_refs.ParsingAReference.test_a_backend_uri_is_not_a_reference",
        scar="s3://bucket/key is read as the store `bucket`: a backend URI slips in as a "
             "reference and binds the entry to one location, which decision 3 rules out"),
    # -- the signature -----------------------------------------------------
    Mutation(
        name="the-path-is-encoded-twice",
        file=SIGV4, search='method.upper(), parts.path or "/",',
        replace='method.upper(), urllib.parse.quote(parts.path or "/"),',
        test="tests.test_sigv4.SignatureMatchesAnIndependentSigner.test_a_key_that_needs_encoding",
        scar="S3 does not double-encode the canonical URI; every key with a space or an "
             "umlaut would be refused with a signature mismatch, and only those"),
    # -- declarations ------------------------------------------------------
    Mutation(
        name="an-unknown-backend-loads",
        file=STORES, search="if backend not in BACKENDS:", replace="if False:",
        test="tests.test_stores.MatchingAddresses.test_an_unknown_backend_is_refused_at_load",
        scar="a declaration naming a backend nothing implements is accepted, and fails "
             "later with an error that names the wrong thing"),
    Mutation(
        name="a-wildcard-outranks-an-exact-name",
        file=STORES, search="        return (3, len(address))", replace="        return (0, len(address))",
        test="tests.test_stores.MatchingAddresses.test_an_exact_address_beats_a_wildcard_whatever_the_file_order",
        scar="review finding: `archive.yaml` with [\"*\"] took a reference meant for a named "
             "local store, and content declared as staying on this machine went to a bucket"),
    Mutation(
        name="a-shorter-prefix-outranks-a-longer-one",
        file=STORES, search="        return (2, len(address) - 1)", replace="        return (2, -(len(address) - 1))",
        test="tests.test_stores.MatchingAddresses.test_a_longer_prefix_beats_a_shorter_one",
        scar="the broader claim wins, and the narrower store never receives what it was declared for"),
    Mutation(
        name="a-tie-is-settled-by-a-filename",
        file=STORES, search="    if len(claimants) > 1:", replace="    if False:",
        test="tests.test_stores.MatchingAddresses.test_two_equal_claims_on_one_store_are_refused",
        scar="two declarations claim one store and whichever sorts first gets the bytes"),
    # -- the local backend -------------------------------------------------
    Mutation(
        name="a-missing-root-is-created",
        file=LOCAL,
        search='        if not self.root.is_dir():\n            raise NotReachable(\n'
               '                f"the directory {self.root} is not there",',
        replace='        self.root.mkdir(parents=True, exist_ok=True)\n'
                '        if not self.root.is_dir():\n            raise NotReachable(\n'
                '                f"the directory {self.root} is not there",',
        test="tests.test_local.LocalStore.test_a_put_into_a_missing_root_creates_nothing",
        scar="an unmounted volume looks exactly like a missing directory; creating it puts "
             "the bytes on the boot disk under the mount point and reports success"),
    Mutation(
        name="an-empty-mount-point-counts-as-the-store",
        file=LOCAL, search="        if not (self.root / MARKER).is_file():", replace="        if False:",
        test="tests.test_local.WhereALocalStoreMayLive.test_an_empty_mount_point_is_not_a_store",
        scar="review finding: an unmounted volume leaves an empty directory on Linux and a "
             "stale /Volumes/x on macOS; is_dir() says yes and the bytes land on the boot disk"),
    Mutation(
        name="a-relative-root-is-accepted",
        file=LOCAL, search="        if not self.declared.strip() or not self.root.is_absolute():",
        replace="        if False:",
        test="tests.test_local.WhereALocalStoreMayLive.test_a_relative_or_empty_root_is_refused",
        scar="review finding: a relative path resolves against the current directory, usually "
             "the Bridge's own work tree, the one place this family keeps content out of"),
    Mutation(
        name="init-creates-the-root",
        file=LOCAL,
        search='        if not self.root.is_dir():\n            raise NotReachable(f"the directory {self.root} '
               'is not there, so it cannot be marked",',
        replace='        self.root.mkdir(parents=True, exist_ok=True)\n'
                '        if not self.root.is_dir():\n            raise NotReachable(f"the directory {self.root} '
                'is not there, so it cannot be marked",',
        test="tests.test_local.WhereALocalStoreMayLive.test_init_marks_an_existing_directory_and_creates_nothing_else",
        scar="init that creates the root turns the marker into a formality: it marks the empty "
             "mount point it was supposed to tell apart from the volume"),
    Mutation(
        name="a-link-may-lead-out-of-the-root",
        file=LOCAL, search="if not target.is_relative_to(base):", replace="if False:",
        test="tests.test_local.LocalStore.test_a_key_cannot_escape_the_root_through_a_link",
        scar="a symlink inside a store reads and writes wherever it points"),
    # -- the S3 backend ----------------------------------------------------
    Mutation(
        name="a-404-is-not-named-not-found",
        file=S3, search="if exc.code == 404:", replace="if exc.code == 4040:",
        test="tests.test_s3.S3Store.test_a_404_is_not_found",
        scar="a missing object becomes a generic refusal, and a caller cannot tell content "
             "that went missing from a request it got wrong"),
    Mutation(
        name="a-403-reads-as-something-else",
        file=S3, search="if exc.code == 403:", replace="if exc.code == 4030:",
        test="tests.test_s3.S3Store.test_a_403_is_denied_and_not_missing",
        scar="a store that is there and said no must not read like one that is not there"),
    Mutation(
        name="an-unreachable-service-reads-as-missing-content",
        file=S3, search='raise NotReachable(f"{self.endpoint} did not answer',
        replace='raise NotFound(f"{self.endpoint} did not answer',
        test="tests.test_s3.S3Store.test_a_closed_port_is_not_reachable",
        scar="the exact confusion decision 5 names: a machine problem reported as content "
             "that went missing, which invites somebody to write it again"),
    Mutation(
        name="the-payload-hash-is-not-the-body",
        file=S3, search="payload_sha256=sha, body=body", replace="payload_sha256=EMPTY_PAYLOAD, body=body",
        test="tests.test_s3.S3Store.test_the_payload_hash_travels_with_the_request",
        scar="S3 refuses a body whose hash is not the one signed; a client that signs the "
             "empty payload for every PUT works for empty files only"),
    Mutation(
        name="a-download-cut-short-is-a-success",
        file=S3, search="            if expected_size is not None and size != int(expected_size):",
        replace="            if False:",
        test="tests.test_s3.WhatTheServiceMustNotGetAwayWith.test_a_download_cut_short_is_not_a_success",
        scar="review finding: read() returns an empty chunk on an early close; a recording cut "
             "at sixty percent was kept, cached, and its hash printed as the object's"),
    Mutation(
        name="the-recorded-hash-is-ignored",
        file=S3, search="            if expected_sha and got != expected_sha:", replace="            if False:",
        test="tests.test_s3.WhatTheServiceMustNotGetAwayWith.test_bytes_that_differ_from_the_recorded_hash_are_refused",
        scar="bytes that are not the ones written are served under the key that named them"),
    Mutation(
        name="redirects-are-followed",
        file=S3, search="_OPENER = urllib.request.build_opener(_RefuseRedirects)",
        replace="_OPENER = urllib.request.build_opener()",
        test="tests.test_s3.WhatTheServiceMustNotGetAwayWith.test_a_redirect_is_not_followed_and_the_signature_stays_home",
        scar="review finding: urllib copies the signed Authorization header to whatever host a "
             "307 names, and the signature reads that object for about fifteen minutes"),
    Mutation(
        name="a-header-error-shows-the-header",
        file=S3, search="        except ValueError:\n", replace="        except ZeroDivisionError:\n",
        test="tests.test_s3.WhatTheServiceMustNotGetAwayWith.test_a_credential_a_header_cannot_carry_is_refused_without_showing_it",
        scar="review finding: http.client's ValueError names the header value, and for "
             "Authorization that is the access key and the signature"),
    # -- the resolver ------------------------------------------------------
    Mutation(
        name="the-cache-is-never-asked",
        file=RESOLVER, search="hit = self.cache.get(expect_sha256)", replace="hit = None",
        test="tests.test_cache.ReadCache.test_a_second_read_is_served_from_the_cache_and_says_so",
        scar="every read goes to the store, and the offline answer of decision 5 is gone"),
    Mutation(
        name="the-cache-does-not-answer-offline",
        file=RESOLVER,
        search="        hit = self._hit(ref, expect)\n        if hit is not None:\n            return hit\n"
               "        with self._explained(store):\n            backend = self.backend(store)\n",
        replace="        self.backend(store).stat(ref.key)\n"
                "        hit = self._hit(ref, expect)\n        if hit is not None:\n            return hit\n"
                "        with self._explained(store):\n            backend = self.backend(store)\n",
        test="tests.test_cache.ReadCache.test_an_offline_read_is_served_from_the_cache",
        scar="asking the store before the cache makes the cache useless exactly when the "
             "store cannot be reached"),
    Mutation(
        name="content-with-the-wrong-hash-is-served",
        file=RESOLVER, search="if expect and got != expect:", replace="if False:",
        test="tests.test_cache.ReadCache.test_content_that_does_not_match_its_hash_is_refused_and_not_cached",
        scar="the entry tracks a hash so that different bytes under the same key are noticed; "
             "without the check they are served, and cached under the wrong name"),
    Mutation(
        name="an-oversized-object-is-downloaded-first",
        file=RESOLVER, search="            if head.size is not None and head.size > self.cache.max_bytes:",
        replace="            if False:",
        test="tests.test_cache.ReadCache.test_an_object_too_large_for_the_cache_is_refused_before_it_is_downloaded",
        scar="review finding: the whole object crossed the network before anything noticed it "
             "could never be cached"),
    Mutation(
        name="a-miss-does-not-explain-itself",
        file=RESOLVER, search='            exc.hint = f"{exc.hint}\\n  {note}" if exc.hint else note',
        replace="            exc.hint = exc.hint",
        test="tests.test_cli.AMissExplainsItself.test_the_declared_reachability_is_named_in_a_miss",
        scar="review finding: the schema promised reachable_from explains a miss, and nothing read it"),
    Mutation(
        name="a-store-nobody-declared-is-not-named",
        file=ERRORS, search="EX_UNDECLARED = 4 ", replace="EX_UNDECLARED = 3 ",
        test="tests.test_cli.ThreeNamedOutcomes.test_a_store_this_instance_does_not_declare",
        scar="a reference written for another instance reads like a missing object"),
    Mutation(
        name="a-malformed-reference-is-one-of-the-three",
        file=ERRORS, search='outcome = "malformed-reference"', replace='outcome = "not-found"',
        test="tests.test_cli.ThreeNamedOutcomes.test_a_malformed_reference_is_a_different_answer",
        scar="a typo in a reference must not read like content that went missing"),
    Mutation(
        name="a-failed-write-is-spooled",
        file=RESOLVER, search="            stat = self.backend(store).put(ref.key, source)\n",
        replace="            try:\n                stat = self.backend(store).put(ref.key, source)\n"
                "            except Exception:\n"
                "                (self.root / '.bridge').mkdir(parents=True, exist_ok=True)\n"
                "                shutil.copyfile(source, self.root / '.bridge' / 'spool.bin')\n"
                "                raise\n",
        test="tests.test_cli.NoWriteIsQueued.test_a_failed_put_leaves_nothing_behind",
        scar="a spool is a second source of truth that reports a write as landed while it is "
             "not; decision 5 refuses it"),
    # -- the cache ---------------------------------------------------------
    Mutation(
        name="an-object-larger-than-the-cap-is-cached",
        file=CACHE, search="        if size > self.max_bytes:\n            return None",
        replace="        if False:\n            return None",
        test="tests.test_cache.ReadCache.test_an_object_larger_than_the_cap_is_not_cached",
        scar="one large object evicts everything else and then sits over the cap itself"),
    Mutation(
        name="the-cap-is-not-enforced",
        file=CACHE, search="            if total <= self.max_bytes:\n                break",
        replace="            if True:\n                break",
        test="tests.test_cache.ReadCache.test_the_cache_stays_under_its_cap_by_dropping_the_oldest",
        scar="a cache without a cap is a second copy of every store on the laptop's disk"),
    Mutation(
        name="a-read-does-not-keep-an-entry",
        file=CACHE, search="            os.utime(path)", replace="            path.stat()",
        test="tests.test_cache.ReadCache.test_a_read_keeps_an_entry_young",
        scar="review finding: least recently WRITTEN evicts the object read a minute ago"),
    Mutation(
        name="a-cached-file-stays-writable",
        file=CACHE, search="        os.chmod(target, _READ_ONLY)", replace="        os.chmod(target, 0o644)",
        test="tests.test_cache.ReadCache.test_a_cached_file_is_read_only",
        scar="review finding: `path` hands out the cache file; edited in place, every later hit "
             "serves the edit under the original hash"),
    Mutation(
        name="forget-forgets-nothing",
        file=CACHE, search="        path.unlink()\n        return True", replace="        return True",
        test="tests.test_cli.InitAndForget.test_forget_drops_a_cached_copy",
        scar="an erased voiceprint stays servable from the cache for as long as its hash is known"),
    Mutation(
        name="an-uppercase-hash-is-refused",
        file=CACHE, search='    text = str(value or "").strip().lower()', replace='    text = str(value or "").strip()',
        test="tests.test_cli.UsageIsNamedAndNeverATraceback.test_an_uppercase_hash_is_the_same_hash",
        scar="review finding: Get-FileHash prints upper case, and the same hash was a usage error"),
    Mutation(
        name="a-bad-hash-is-not-a-usage-error",
        file=CACHE, search='        raise UsageError(f"{value!r} is not a sha256',
        replace='        raise ValueError(f"{value!r} is not a sha256',
        test="tests.test_cli.UsageIsNamedAndNeverATraceback.test_a_hash_that_is_not_one_is_a_usage_error",
        scar="review finding: a mistyped hash escaped as a traceback with no outcome word"),
    # -- credentials -------------------------------------------------------
    Mutation(
        name="the-environment-is-ignored",
        file=CREDS, search="    if access and secret:\n        return _clean(access, store), _clean(secret, store)",
        replace="    if False:\n        return _clean(access, store), _clean(secret, store)",
        test="tests.test_cli.CredentialsAreReferences.test_credentials_can_come_from_the_environment",
        scar="`secrets run --env` is how a caller hands a credential over without argv; "
             "ignoring it forces every caller through a second resolution"),
    Mutation(
        name="one-pair-of-keys-for-every-store",
        file=CREDS, search='    stem = "OBJECT_STORE_" + store_name.upper().replace("-", "_")',
        replace='    stem = "OBJECT_STORE"',
        test="tests.test_cli.CredentialsAreReferences.test_one_stores_keys_in_the_environment_do_not_open_another",
        scar="review finding: store B's endpoint received store A's access key and a request "
             "signed with it, and the refusal read as a policy problem"),
    Mutation(
        name="a-trailing-newline-breaks-the-key",
        file=CREDS, search="    value = str(value).strip()", replace="    value = str(value)",
        test="tests.test_cli.CredentialValuesStayOutOfSight.test_a_trailing_newline_in_a_stored_key_is_forgiven",
        scar="a stored secret ending in a newline is the common case, not a broken key"),
    Mutation(
        name="a-key-with-a-line-break-is-sent",
        file=CREDS, search="    if not value or any(ord(c) < 0x21 or ord(c) > 0x7E for c in value):",
        replace="    if not value:",
        test="tests.test_cli.CredentialValuesStayOutOfSight.test_a_key_with_a_line_break_inside_is_named_without_being_shown",
        scar="the key goes into a header http.client refuses, and the refusal names the value"),
    Mutation(
        name="no-credential-reads-like-any-error",
        file=ERRORS, search='outcome = "credentials-unavailable"', replace='outcome = "error"',
        test="tests.test_cli.CredentialsAreReferences.test_no_way_to_resolve_a_credential_is_named_as_such",
        scar="a store that cannot be opened must not read like a store that is not there"),
    # -- the output --------------------------------------------------------
    Mutation(
        name="fetch-echoes-the-content",
        file=CLI, search='        print(f"wrote {result.path}  {_line(result)}")',
        replace='        print(f"wrote {result.path}  {_line(result)}  "'
                ' + open(result.path, encoding="utf-8", errors="replace").read())',
        test="tests.test_cli.ContentNeverReachesTheOutput.test_no_command_prints_the_bytes_it_moves",
        scar="decision 6: bytes never enter a context window; a multi-gigabyte object ends "
             "the session that asked for it"),
    Mutation(
        name="a-path-cache-hit-does-not-say-so",
        file=CLI, search="        print(result.path)\n        print(f\"served from: {result.source}\", file=sys.stderr)",
        replace="        print(result.path)\n        print(\"served from: store\", file=sys.stderr)",
        test="tests.test_cli.ACacheHitSaysSo.test_path_reports_where_the_bytes_came_from",
        scar="an answer from the cache while the store is down must be recognisable as one"),
    Mutation(
        name="a-fetch-cache-hit-does-not-say-so",
        file=CLI,
        search='        print(f"wrote {result.path}  {_line(result)}")\n'
               '        print(f"served from: {result.source}", file=sys.stderr)',
        replace='        print(f"wrote {result.path}  {_line(result)}")\n'
                '        print("served from: store", file=sys.stderr)',
        test="tests.test_cli.ACacheHitSaysSo.test_fetch_reports_where_the_bytes_came_from",
        scar="review finding: only `path` was held to reporting a hit"),
    Mutation(
        name="an-unexpected-failure-prints-its-message",
        file=CLI, search='        failure = Unexpected(f"{type(exc).__name__} (its message is not shown; it is not ours)")',
        replace='        failure = Unexpected(f"{type(exc).__name__}: {exc}")',
        test="tests.test_cli.CredentialValuesStayOutOfSight.test_an_unexpected_failure_shows_its_type_and_not_its_message",
        scar="an exception message that is not the resolver's can carry anything, a signed "
             "header included"),
    # -- the guard ---------------------------------------------------------
    Mutation(
        name="the-guard-lets-the-network-through",
        file=SUPPORT, search="        if host not in LOOPBACK:", replace="        if False:",
        test="tests.test_guard.TheGuardHolds.test_a_connection_off_loopback_is_refused",
        scar="without it a case can pass on the strength of the developer's live bucket"),
    Mutation(
        name="the-guard-lets-programs-start",
        file=SUPPORT, search='            ("subprocess.Popen", _no_programs),\n', replace="",
        test="tests.test_guard.TheGuardHolds.test_starting_a_program_is_refused",
        scar="the resolver needs no child process; one that appears is a client tool with "
             "live credentials"),
)
