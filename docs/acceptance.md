# Acceptance: requirements, tests and the runs that actually took place

This file maps every row of the test tables of the build specification (section 12) and of the kill extension
specification (section 7) to the tests that prove it, and lists the runs that really took place. The levels:

- **Collector** (`internal/collector/ebpf`): against the real kernel, no mocks (see
  [compatibility.md](compatibility.md)).
- **Agent** (`tests/integration`): the built `process-watcher` binary in the initial PID namespace of a real kernel,
  with own test processes, a JSONL file and real network targets on `127.0.0.1`/`::1`.
- **Unit** (other packages): deterministic, on every platform; the replay collector replaces the kernel only here.

Commands: `make test` (unit, macOS or Linux), `make test-docker` (collector, response and agent in a privileged
container, `--pid=host`), `make test-vm ARCH=… KERNEL=…` or `make test-vm-matrix` (collector in kernel/architecture
variants), `make test-vm-e2e` (agent in a QEMU guest), `make test-vm-systemd` (the service under a real systemd),
`make bench-docker` (measurements).

## Build specification, section 12

| Scenario | Tests |
| --- | --- |
| Root already running before the agent starts | Agent `TestRootRunningBeforeStartIsDiscoveredOnce`; Unit `TestStartupDiscoversRootAndLivingDescendants`, `TestStartupDoesNotInventAncestry`; App `TestStartupSequenceDiscoversThenReady` |
| Root starts only later | Agent `TestRootStartingLaterAndTheChainShareOneRoot`, `TestLivingChildrenOfANewRootAreDiscovered`; Unit `TestRootStartsLater`, `TestRootAdmittedAtRuntimeAsksForAReconciliation`; App `TestLivingChildrenOfARootThatAppearedAtRuntimeAreDiscovered` |
| `nginx → helper → sh → curl` | Agent `TestRootStartingLaterAndTheChainShareOneRoot`; Unit `TestEveryGenerationSharesTheRoot` |
| Child lives only a few milliseconds | Collector `TestShortLivedChild`; Agent `TestShortLivedChildrenNeedNoProcAccess` (at least 1000 children, instances and execs compared against the logged identities, no `/proc` access needed) |
| Child forks but does not exec | Collector `TestForkWithoutExec` (`fork`, `clone3`); Agent `TestForkWithoutExecRepeatedExecAndFailedExec`; Unit `TestForkWithoutExecHasItsOwnLifecycle` |
| Repeated exec in the same instance | Collector `TestRepeatedExecKeepsIdentity`; Agent `TestForkWithoutExecRepeatedExecAndFailedExec`; Unit `TestRepeatedExecKeepsIdentityAndCounts` |
| Exec fails | Collector `TestFailedExecIsNotReported`; Agent `TestForkWithoutExecRepeatedExecAndFailedExec` |
| Excluded helper starts a shell | Agent `TestExcludedHelperDoesNotHideItsDescendants`; Unit `TestExclusionIsReevaluatedPerEvent` |
| Excluded fork, later a different exec | Unit `TestExclusionIsReevaluatedPerEvent`, `TestExclusionOnArgumentsNeedsThem` |
| Root ends, child lives on | Agent `TestOrphanStaysInItsTree`; Unit `TestRootEndsChildSurvives` |
| PID is reused | Collector `TestReusedPIDGetsANewIdentity` (forced through `ns_last_pid`); Unit `TestPIDReuseNeverInheritsState`; Response `TestTargetEndsAfterTheIdentityCheckAndThePIDIsReused` |
| Threads and exec from a worker thread | Collector `TestThreadsAreNotProcesses` (fork from a non-leader thread, exec from a non-leader thread, leader ends before the last thread) |
| Fork from a worker, vfork, clone3 and double fork | Collector `TestThreadsAreNotProcesses`, `TestForkWithoutExec` (`clone3`), `TestDoubleFork`; `vfork` is the start path of every child of the test helpers: Go starts children with `clone(CLONE_VFORK\|CLONE_VM)`, all collector tests with child processes run through it |
| Two matching independent roots | Agent `TestTwoIndependentRootsAndMatchingWorkers`; Unit `TestTwoIndependentRoots` |
| Forks during the initial snapshot | Unit `TestForkDuringTheSnapshotIsNotDuplicated`, `TestSnapshotNeverResurrectsAnExitedProcess`, `TestPreVisitExecIsAlreadyReflected`; Collector `TestSnapshotAndLiveShareIdentity` |
| Limited depth or truncated ancestor array | Agent `TestDepthLimitSuppressesOnlyTheOutput`; Unit `TestDepthLimitOnlyLimitsOutput`, `TestAncestorArrayIsBoundedButDepthIsNot` |
| Unknown or unreadable metadata | Unit `TestMissingMetadataKeepsTheRecord`, `TestInvalidUTF8IsSanitizedAndFlagged`; Collector `TestDeletedAndFilelessExecutables`, `TestLongPathAndArgumentLimits` |
| Argument contains a newline or quotation marks | Agent `TestSpecialArgumentsKeepEveryLineParsable`; Unit `TestMarshalLineIsOneLineWithUnescapedHTML` |
| YAML, boolean overrides and list flags | Unit `TestFlagsOverrideYAML`, `TestListFlagSemantics`, `TestBoolFlags`, `TestEveryYAMLLeafHasExactlyOneFlag`, `TestFlagTableMatchesSpecification`, `TestPrintConfigCoversEveryLeafInOrder` |
| Faulty YAML, duplicate keys, unknown option | Unit `TestYAMLErrors`, `TestYAMLValidationErrorsCarryLines`, `FuzzYAMLDocument`; Agent `TestConfigurationErrorsStartNothing` |
| Config next to the binary and invocation from another directory | Unit `TestFileSearchOrder`, `TestBinaryDirectoryResolution`, `TestRealSymlinkedBinaryFromAnotherDirectory`, `TestRelativePathsResolveAgainstTheWorkingDirectory`; the release smoke test runs the shipped binary with the shipped configuration from another directory |
| File rotates during many events | Unit `TestFileRotation`, `TestFileConcurrentWritesWithRotation`; Agent `TestLogRotationKeepsEveryLine`, `TestOutRotationUnderLoad` |
| Second writer, symlink and broken file tail | Unit `TestFileSecondWriterRefused`, `TestFileLockAcrossProcesses`, `TestFileSymlinkAndSpecialFilesRefused`, `TestFileTornTailRepair`; Agent `TestOnlyOneWriterPerLogAndNoSymlinks`, `TestOutLogFileSafety` |
| TCP partial write and connection loss | Unit `TestTCPRetriesWholeLineAfterConnectionResetMidLine`, `TestTCPRetryAfterPartialWriteOnFakeConn`; Agent `TestOutTCPReconnect` |
| UDP event exceeds the limit | Unit `TestOversizeEventDropsOnlyUDP`, `TestUDPMaxBytesBoundary`; Agent `TestOutUDPSizeLimit` |
| Webhook returns 429, 500, 400, redirect or timeout | Unit `TestWebhookStatusHandling`, `TestWebhookDoesNotFollowRedirects`, `TestWebhookTimeoutIsRetried`; Agent `TestOutWebhookBehaviour` |
| Remote target hangs, other targets work | Unit `TestHangingRemoteDoesNotSlowOthers`, `TestEnqueueStaysNonBlockingWithStalledTCPServer`; Agent `TestOutHangingTCPTarget`, `TestOutAllOutputsIdentical` |
| Invalid TLS certificate and missing token | Unit `TestTCPTLSNeverFallsBackToPlaintext`, `TestWebhookSecretsNeverLeak`, `TestWebhookTokenCheckDependsOnTheCommand`; App `TestMissingWebhookTokenIsAConfigurationError`; Agent `TestOutTCPTLS` |
| Missing privileges, BTF or hooks | Agent `TestWithoutPrivilegesTheAgentRefusesWithExitCode3`; App `TestPrerequisitesAreCheckedBeforeAnySideEffect`; Collector `TestLockdownConfidentialityIsNamed` (kernel with `lockdown=confidentiality`), `TestWireContract`. A kernel **without BTF** was not available: the diagnosis `kernel BTF` is backed by the code (`checkKernelBTF`) only, not executed on such a kernel |
| Forced ring buffer / process state loss | Collector `TestLossIsCountedInTheKernel`; Agent `TestOverloadIsMeasuredAndReported`; App `TestRecordLossBecomesAGapAndAReconciliation`, `TestLossDuringTheStartupWindowIsReported`, `TestProcessTableLimitIsReportedAsAGap`; Unit `TestProcessTableLimit`, `TestReconcileAfterLossMarksWhatItDiscovers` |
| Full disk and SIGTERM with full queues | App `TestLocalLogFailureEndsTheAgentWithExitCode1`, `TestLocalLogFailureAtShutdownIsAFailureOfTheRun`; Agent `TestOutLocalLogFailureIsFatal`, `TestOutShutdownWithQueuedEvents`; Unit `TestShutdownDeliversQueuedEvents`, `TestShutdownDeadlineAbortsInFlightWork` |

Further required checks:

| Requirement | Test or run |
| --- | --- |
| At least 1000 children after `agent.ready`, zero losses under normal load | Agent `TestShortLivedChildrenNeedNoProcAccess` |
| Separate overload test with explicitly expected and reported losses | Agent `TestOverloadIsMeasuredAndReported` |
| Race tests for the Go pipeline | `go test -race` over all packages (macOS) and `go test -race ./internal/...` on Linux in a container (see the runs) |
| Both delivery architectures | Collector and agent suites on arm64 **and** amd64 (QEMU matrix) and arm64 natively; cross builds for both (`make build-linux`) |
| CPU, RSS, throughput, latency, loss counters at rest and under load | `TestMeasureResourcesAndThroughput` (`make bench-docker`), results in [measurements.md](measurements.md) |
| Format contract | `schema/event.schema.json`; every event produced by all agent, app and process model tests is validated against it; golden files in `testdata/golden/` |

## Kill extension specification, section 7

| Scenario | Tests |
| --- | --- |
| No active feature | Agent `TestKillFeatureOff`; Unit `TestNoRulesNoActions` |
| String/regex hit in an observed child | Agent `TestKillStringAndRegexHitInDirectChild`; Unit `TestDescendantHitWritesTheDecisionBeforeTheAttempt` |
| Grandchild or deeper descendant hits | Agent `TestKillGrandchildAndDeeper`; Unit `TestGrandchildGetsTheSameReactionWithTheOriginalRoot` |
| Root or foreign process hits | Agent `TestKillNeverTouchesWatchedRootOrStrangers`, `TestKillTheAgentIsNeverATarget`; Unit `TestRootsAndStrangersAreNeverTargets`, `TestAgentAndInitAreNotEligible` |
| Hit in arguments while capture is disabled | Agent `TestKillArgvWithoutCaptureRefusesToStart`, `TestKillArgvRules` |
| Broken regex, list overrides, boolean overrides | Agent `TestKillConfigPriority`; Unit `TestCompileErrors` (killrule), `TestCompileRegex`, `TestFlagsOverrideYAML`, `TestBoolFlags` |
| Exclusion or limited output depth also applies | Agent `TestKillIndependentOfExclusionsAndDepth`; Unit `TestExclusionsAndOutputDepthDoNotShieldATarget` |
| Several rules and duplicate events hit | Agent `TestKillSeveralRulesOneAttempt`; Unit `TestSeveralRulesOneActionPerExecGeneration`, `TestRepeatedSnapshotsDoNotRepeatTheAction` |
| Excluded or ended parent process | Agent `TestKillParentEndedOrExcluded`; Unit `TestParentGoneOrExcludedDescendantsAreStillJudged` |
| Already living child at start | Agent `TestKillAlreadyRunningChildAtStart` |
| Short-lived process is already gone | Agent `TestKillProcessThatEndedBeforeTheAgentReacts`, `TestKillShortLivedProcess`; Response `TestVanishedTargetIsAnExpectedOutcome` |
| PID change between detection and opening the handle | Response `TestPIDChangedBetweenDetectionAndOpeningTheHandle` (state machine with a simulated kernel), `TestRealPidfdBindsTheSignalToThatInstance` (real pidfd) |
| End after the identity check and reuse of the PID | Response `TestTargetEndsAfterTheIdentityCheckAndThePIDIsReused`, `TestSignalGoesThroughTheHandleAndKillsTheTarget` |
| Intervening exec or missing current match data | Agent `TestKillInterveningExecIsNotKilledForAStaleMatch`, `TestKillExecChainIsJudgedAgain`; Response `TestChangedProgramOrArgumentsAreNotKilled`, `TestCurrentValuesThatCannotBeReadProveNothing`, `TestIdentityNotProvableIsSkipped` |
| Truncated value would hit a regex end anchor | Agent `TestKillNeverOnTruncatedValue`; Unit `TestIncompleteValuesNeverFeedARule` |
| Dry run | Agent `TestKillDryRun`; Unit `TestDryRunIsMarkedAndExitsDoNotTrigger`; Response `TestDryRunNeverTouchesTheKernel` |
| Permission error, full queue, FD limit, shutdown | Agent `TestKillPermissionDenied`, `TestKillFileDescriptorLimit`; Response `TestBoundedQueueAndShutdown`, `TestErrorsAreReportedSeparatelyAndNeverRepeated`, `TestSignalLoopsDoNotExist` |
| Remote outages or duplicate remote delivery | Agent `TestKillRemoteOutage`; Response `TestAuditWriteFailureStopsFurtherActions` |

Also: `TestKillOnForkWithInheritedImage` (evaluation at `process.fork` with inherited image/path only),
`TestKillFailedActionDoesNotBlockTheNextExec`, `TestKillReactionLatency` (measurement, see
[measurements.md](measurements.md)). Real signal tests use exclusively own, isolated test processes with controlled
names; the test binary serves as the helper, no user accounts are changed and no `useradd` is run. The actual end of
the process is verified at the kernel in addition to the audit.

## PHP use case ([php.md](php.md))

The PHP guide has its own evidence. The Agent tests use PHP-shaped helper programs (a service master, workers, `/bin/sh`,
`/bin/true`, a copy of `sleep`), the lab uses the real nginx, Apache and PHP 8.4 of Debian 13
([tests/php](../tests/php/README.md)).

| Scenario | Tests |
| --- | --- |
| Which executable to watch for NGINX/Apache + FPM, mod_php, php-cgi, CLI; watches that see nothing | Agent `TestPHPWatchTargetsFollowTheExecutionModel`, `TestPHPWatchSubstringsSelectTheExpectedExecutables`; lab `deployments:*` |
| Shell, interpreter and direct launches below a worker keep their command lines | Agent `TestPHPSpawnedProgramsKeepTheirCommandLines`; lab `argv` |
| Long arguments around the default limit, an inline script that starts near the end, configurable limits, flags, refused values | Agent `TestPHPInlineCommandsAroundTheDefaultLimit`, `TestPHPInlineCodeThatStartsNearTheEndOfTheCapture`, `TestPHPConfigurableArgumentLimitsKeepLongInlineCommands`, `TestPHPArgumentLimitFlagsAreEquivalentToYAML`, `TestPHPArgumentLimitsOutsideTheSupportedRangeAreRefused`; Collector `TestLongPathAndArgumentLimits`, `TestConfigurableArgumentLimits`; Unit `TestParseArgs*`, `TestArgLimitsNormalized`, `TestStartedReportsTheCaptureLimits` |
| Completeness is explicit; a cut argument never matches | Unit `TestCompleteArgvIsMarkedComplete`, `TestIncompleteArgvCarriesTheEvidence`, `TestThePartialArgumentNeverFeedsARule`, `TestPartialArgumentIsSanitized`; Agent `TestPHPLargeArgumentsSurviveEveryTransport` (file, TCP, webhook identical; UDP drops what exceeds the datagram limit) |
| Short-lived programs, exited parents, worker replacement, reload, fork without exec | Agent `TestPHPShortLivedProgramsAndExitedParents`, `TestPHPWorkerReplacingItsExecutableIsOneProcessWithTwoExecs`, `TestPHPWorkerReplacementKeepsTheTree`, `TestPHPReloadReexecutesTheMasterAndForksANewOne`, `TestPHPForkWithoutExecIsAForkWithTheInheritedImage`; lab `fpm-lifecycle` |
| Activity inside the worker (a network connection without a child process) | Agent `TestPHPInProcessNetworkConnectionIsNotAProcessEvent`; lab `blindspot` (a documented blind spot, not a covered case) |
| A broad rule kills the workers; the guard prevents it; narrow rules, dry run, roots | Agent `TestPHPBroadKillRuleKillsTheWorkersItWasMeantToProtect`, `TestPHPSpareRootImageKeepsWorkersAliveAndStillKillsHelpers`, `TestPHPNarrowRulesKillShellsAndInterpretersButNotWorkers`, `TestPHPDryRunReportsWithoutKilling`, `TestPHPRootsAreNeverKilled`, `TestPHPWorkerThatReplacesItselfWithAKillableProgramIsKilled`; Unit `TestBroadRuleHitsForkedWorkersWithoutTheGuard`, `TestSpareRootImage*`, `TestKillWarnings`, `TestStartedReportsTheKillSafeguards`; lab `killrules:*` |
| The kill audit explains itself | Agent `TestPHPKillAuditExplainsItselfThroughTheChain`; Unit `TestKillAuditListsTheAncestorsWithTheirArguments`, `TestKillChain*` |
| Reaction time against slow and fast programs | Agent `TestPHPKillReactionAgainstSlowAndFastPrograms` (measurement); lab `latency` (numbers in [php.md](php.md#6-response-rules)) |

No test uses an exploit, a payload or a vulnerability: every program that the tests start is a harmless fixed command.
[php-fpm-kill-signatures.yaml](../examples/php/php-fpm-kill-signatures.yaml) ships only placeholder entries for
command-line signatures of specific shell payloads; process-watcher provides no such patterns itself (docs/php.md
section 6) and none were written for this acceptance ledger either.

## Runs that actually took place (as of 2026-10-18)

| Run | Environment | Result |
| --- | --- | --- |
| `go vet ./...` | macOS, `GOOS=linux` for `arm64` and `amd64` | clean |
| `go test -race ./...` | macOS arm64 | all packages passed |
| `go test ./...` as a non-root user on Linux (what the CI unit job does) | Linux arm64 container | all packages passed; tests that need the agent binary or root skip without them and run when `PW_AGENT_BIN` is set |
| Fuzz `FuzzYAMLDocument`, `FuzzCommandLine` | 30 s each, final tree | 566,462 and 998,035 executions, no failure |
| `make test-race-docker` | Linux arm64 container | 14 packages passed (final tree) |
| `make test-docker` (the tree with the PHP changes) | Docker VM, kernel 6.12.54, arm64, native | 123 passed, 0 failed, 2 skipped (lockdown test, measurement test), about 3 min 30 s; `procfs` 4, `response` 16, `collector` 26, agent 77. The tree of v0.1.0 passed 98 (three runs); one attempt stopped before the end-to-end binary started (`./e2e.test: not found`, a file-sharing glitch of Docker Desktop: the file existed and the immediate repeat passed) |
| `tools/ci/kernel-tests.sh` (the privileged job of the CI workflow) | privileged container, kernel 6.12.54, arm64 | 123 passed, 0 failed, 2 skipped, 3 min 27 s |
| PHP lab (`tests/php/run.sh`, see [tests/php](../tests/php/README.md)) | Docker VM (kernel 6.12.54, arm64, native); Debian 13 with nginx 1.26.3, Apache 2.4.69 (prefork with mod_php, event with proxy_fcgi, mod_fcgid) and PHP 8.4.26 (FPM, CGI, CLI), the real agent | 15 runs, 108 checks passed, 0 failed, about 4 minutes with the lab image already built |
| `tests/php/names-images.sh` | Docker: official `php` images (fpm, fpm-alpine, apache, cli), Ubuntu 24.04, Debian 12, Rocky 9 | executable names and image paths read from the real systems (behind the tables of [php.md](php.md#2-which-executable-to-watch)); no behavior checks |
| `make bench-docker`, three runs on the final tree | as above, nothing else running | no lost record, CPU per process start within about 10 % of the measurement of the v0.1.0 tree; see [measurements.md](measurements.md) |
| Collector suite, 3 kernels × 2 architectures | QEMU (emulated CPU) | 26 passed, 0 failed, 1 skipped (the lockdown test, which needs a locked-down kernel) on each of the six combinations, 28 to 83 s per VM; run on the final tree |
| Collector lockdown test with `lockdown=confidentiality` | the same six combinations | passed on all six (final tree) |
| Agent end-to-end (`make test-vm-e2e`, final tree, 77 tests including the 23 PHP tests) | Ubuntu 5.15, arm64, QEMU | 77 passed, 0 failed, 1 skipped (measurement test), 424 s. A first batch on the tree before the last test fix failed on this combination: one PHP test read the exit event of `/bin/true` before the agent had logged it and panicked (a test race under emulation, not an agent defect); the test now waits for that event, and all six combinations were run again from the start |
| Agent end-to-end | Ubuntu 5.15, amd64, QEMU | 77 passed, 0 failed, 1 skipped, 581 s |
| Agent end-to-end | Ubuntu 6.8, arm64, QEMU | 77 passed, 0 failed, 1 skipped, 454 s |
| Agent end-to-end | Debian 6.12, arm64, QEMU | 77 passed, 0 failed, 1 skipped, 400 s |
| Agent end-to-end | Ubuntu 6.8, amd64, QEMU | 77 passed, 0 failed, 1 skipped, 655 s |
| Agent end-to-end | Debian 6.12, amd64, QEMU | 77 passed, 0 failed, 1 skipped, 612 s |
| systemd service (`make test-vm-systemd`), scenarios S1 to S8 | QEMU guest (emulated CPU) with **systemd 249.11 as PID 1** (Ubuntu 22.04 userland), the unit installed by `packaging/install.sh`; all six combinations: Ubuntu 5.15, Ubuntu 6.8 and Debian 6.12, each on arm64 and amd64 | 140 checks passed, 0 failed on each combination, 195 to 220 s per run (three runs in parallel; final tree, final test script). A first run of the tree with the PHP changes failed one check on amd64 Debian 6.12 (S7b.1: the test read the agent's exit status and the restart count in separate `systemctl` calls, and the restart pause ended between them, a race of the test under emulation); the check now takes one snapshot, S7b then passed three times in a row on that combination, and the complete suite was run again on all six. Covered: `systemd-analyze verify` and `security` (exposure 4.9, "OK"), installation and file modes, start under the hardened unit (capability set, no new privileges, seccomp, host PID namespace and `/proc` view, log directory `0700`/`0600`), observation under the unit (roots, descendants, other users, programs below `/root`, processes that existed before the start, no loss), the kill feature with and without `CAP_KILL`, clean `systemctl stop` (exit 0, `agent.stopped`, no restart), invalid configuration (exit 2, no restart loop), a log path outside `LogsDirectory` (bounded restart loop, then fixed by the documented `ReadWritePaths=` drop-in), `SIGKILL` of the main process (restart after `RestartSec`, new `agent_instance_id`), missing privileges (exit 3, no restart) and every hardening directive in effect. One warning per run: `SystemCallArchitectures=native` cannot be tested because the guest cannot execute a binary of another ABI |
| Release tooling `tools/release` | macOS, Docker (arm64 native, amd64 emulated) | unit tests pass; two builds give byte-identical archives (same `SHA256SUMS`); both binaries are verified static ELF files; extracted from the archive they run (`--version`, `check-config`) in a bare Debian container and find the shipped configuration next to the binary |
| Release tooling, `php/` examples in the archive (2026-10-18) | macOS, Docker (`debian:trixie-slim`, arm64) | a real archive built with `go run ./tools/release`; extracted it holds `php/` with the 7 files of `examples/php/`, mode `0644`; the shipped arm64 binary, run from inside the extracted directory, accepts `--config php/php-fpm-dry-run.yaml` and `--config php/php-fpm-kill-signatures.yaml` as well as the default `process-watcher.yaml`; new unit tests `TestWriteArchiveCreatesSubdirectoryHeaders`, `TestLoadPHPExamples` |
| Executable names of `nc`, `socat`, `telnet`, `perl`, `ruby`, `python3`, `bash`, `sh` (2026-10-18, ad hoc, not a committed test) | Debian 13, via the real agent (Docker VM, kernel 6.12.54, arm64) | `nc`/`nc.openbsd`/`nc.traditional` → image `nc.openbsd` or `nc.traditional`; `ncat` → `ncat`; `socat` → `socat1`; `telnet` → `inetutils-telnet`; `perl` → `perl`; `ruby` → `ruby3.3`; `python3` → `python3.13`; `bash` → `bash`; `sh` → `dash`. The same set on Rocky 9, by executable path only (not through the agent): `nc` → `ncat`, `socat` → `socat` (unversioned), `telnet` → `telnet`, `ruby` → `ruby` (unversioned), `python3` → `python3.9`, `sh` → `bash`. Not checked: Alpine, any other distribution |
| Workflows `ci.yml` and `release.yml` | `actionlint` 1.7.12 | no findings. The commands of both were run locally before the first run on GitHub |
| CI workflow (`ci.yml`), first run on `main` | GitHub-hosted runners `ubuntu-24.04` and `ubuntu-24.04-arm`, kernel `6.17.0-1022-azure` (BTF present, lockdown `none`), the privileged tests run directly on the runner through `sudo` | Vet and unit tests with the race detector, the release dry run, the workflow lint and the reproducibility of the embedded eBPF object passed. `tools/ci/kernel-tests.sh` on amd64 and on arm64: 97 passed, 1 failed, 2 skipped (lockdown test, measurement test) each. The one failure was `TestWithoutPrivilegesTheAgentRefusesWithExitCode3`: the unprivileged test user could not reach the agent binary below `/home/runner`. The test now starts a copy from its own world-accessible directory (checked locally by putting the agent into a directory only root can enter); the next run (commit e805063) passed all five jobs, including both kernel jobs |
| Release workflow (`release.yml`), tag `v0.1.0` on commit e805063 | GitHub Actions | passed: verification of the tag, build of both archives, smoke tests of the shipped archives on amd64 and arm64, publication. Afterwards downloaded: `SHA256SUMS` matches both archives; `gh attestation verify` accepts the build provenance (SLSA v1, workflow `release.yml`, ref `refs/tags/v0.1.0`; one statement lists both archives); `--version` and `check-config` run from each published archive in a bare `debian:trixie-slim` container (arm64 native, amd64 emulated) |
| Reproducibility of the embedded eBPF object | `make generate` on an arm64 host and under amd64 emulation | the same object byte for byte (`839e331c…`), which is what the CI job checks on amd64 runners |

**Open and not executed**
- **CI and release for the changes after v0.1.0:** `ci.yml` and `release.yml` have run on GitHub for the code of
  v0.1.0 (see the runs above). The argument-limit, kill-guard and PHP changes came after that tag and have not been
  through either workflow; a `-rc` tag rehearses the release workflow without publishing a final release.
- A kernel without BTF, kernels of other vendors, kernels other than those listed in
  [compatibility.md](compatibility.md) and real amd64 hardware.
- **systemd:** only version 249 (Ubuntu 22.04) was run. Newer versions handle some sandboxing directives differently;
  `systemd-analyze verify` and a start under the unit are the first things to check there. The unit's
  `SystemCallArchitectures=native` was not exercised (see the warning above).
- **Published archives on real hosts:** the archives of v0.1.0 were downloaded from GitHub, their checksums and
  build provenance attestation verified, and `--version` and `check-config` run from them in bare Debian containers
  (arm64 native, amd64 emulated); the agent from a published archive was not started on a bare-metal or virtual
  machine.
