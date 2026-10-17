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

## Runs that actually took place (as of 2026-10-17)

| Run | Environment | Result |
| --- | --- | --- |
| `go vet ./...` | macOS, `GOOS=linux` for `arm64` and `amd64` | clean |
| `go test -race ./...` | macOS arm64 | all packages passed |
| `go test ./...` as a non-root user on Linux (what the CI unit job does) | Linux arm64 container | all packages passed; tests that need the agent binary or root skip without them and run when `PW_AGENT_BIN` is set |
| Fuzz `FuzzYAMLDocument`, `FuzzCommandLine` | 30 s each | 503,000 and 701,520 executions, no failure |
| `make test-race-docker` | Linux arm64 container | 14 packages passed |
| `make test-docker`, three complete runs (the last one on the final tree) | Docker VM, kernel 6.12.54, arm64, native | 98 passed, 0 failed, 2 skipped each (lockdown test, measurement test), about 3 min 10 s; `procfs` 3, `response` 16, `collector` 25, agent 54. One further attempt on the final tree stopped before the end-to-end binary started (`./e2e.test: not found`, a file-sharing glitch of Docker Desktop: the file existed and the immediate repeat passed) |
| `tools/ci/kernel-tests.sh` (the privileged job of the CI workflow) | privileged container, kernel 6.12.54, arm64 | 98 passed, 0 failed, 2 skipped |
| `make bench-docker` | as above, no parallel VM | see [measurements.md](measurements.md) |
| Collector suite, 3 kernels × 2 architectures | QEMU (emulated CPU) | 25 passed, 0 failed, 1 skipped (the lockdown test, which needs a locked-down kernel) on each of the six combinations, 25 to 66 s per VM; run on the final tree |
| Collector lockdown test with `lockdown=confidentiality` | the same six combinations | passed on all six |
| Agent end-to-end (`make test-vm-e2e`) | Ubuntu 5.15, arm64, QEMU | 54 passed, 0 failed, 1 skipped (measurement test), 342 s |
| Agent end-to-end | Ubuntu 5.15, amd64, QEMU | 54 passed, 0 failed, 1 skipped, 466 s |
| Agent end-to-end | Ubuntu 6.8, arm64, QEMU | 54 passed, 0 failed, 1 skipped, 366 s |
| Agent end-to-end | Debian 6.12, arm64, QEMU | 54 passed, 0 failed, 1 skipped, 324 s |
| Agent end-to-end | Ubuntu 6.8, amd64, QEMU | 54 passed, 0 failed, 1 skipped, 523 s |
| Agent end-to-end | Debian 6.12, amd64, QEMU | 54 passed, 0 failed, 1 skipped, 503 s |
| systemd service (`make test-vm-systemd`), scenarios S1 to S8 | QEMU guest (emulated CPU) with **systemd 249.11 as PID 1** (Ubuntu 22.04 userland), the unit installed by `packaging/install.sh`; all six combinations: Ubuntu 5.15, Ubuntu 6.8 and Debian 6.12, each on arm64 and amd64 | 140 checks passed, 0 failed on each combination, 196 to 222 s per run (three runs in parallel). Covered: `systemd-analyze verify` and `security` (exposure 4.9, "OK"), installation and file modes, start under the hardened unit (capability set, no new privileges, seccomp, host PID namespace and `/proc` view, log directory `0700`/`0600`), observation under the unit (roots, descendants, other users, programs below `/root`, processes that existed before the start, no loss), the kill feature with and without `CAP_KILL`, clean `systemctl stop` (exit 0, `agent.stopped`, no restart), invalid configuration (exit 2, no restart loop), a log path outside `LogsDirectory` (bounded restart loop, then fixed by the documented `ReadWritePaths=` drop-in), `SIGKILL` of the main process (restart after `RestartSec`, new `agent_instance_id`), missing privileges (exit 3, no restart) and every hardening directive in effect. One warning per run: `SystemCallArchitectures=native` cannot be tested because the guest cannot execute a binary of another ABI |
| Release tooling `tools/release` | macOS, Docker (arm64 native, amd64 emulated) | unit tests pass; two builds give byte-identical archives (same `SHA256SUMS`); both binaries are verified static ELF files; extracted from the archive they run (`--version`, `check-config`) in a bare Debian container and find the shipped configuration next to the binary |
| Workflows `ci.yml` and `release.yml` | `actionlint` 1.7.12 | no findings. The workflows themselves have **not** been run on GitHub runners; the same commands were run locally |
| Reproducibility of the embedded eBPF object | `make generate` on an arm64 host and under amd64 emulation | the same object byte for byte (`839e331c…`), which is what the CI job checks on amd64 runners |

**Open and not executed**
- **Workflows on GitHub:** `.github/workflows/ci.yml` and `release.yml` were validated with `actionlint` and their
  commands were run locally, but nothing was executed on GitHub-hosted runners yet. The privileged kernel jobs in CI
  depend on the kernel of the runner (BTF, lockdown), which is only known after the first run.
- A kernel without BTF, kernels of other vendors, kernels other than those listed in
  [compatibility.md](compatibility.md) and real amd64 hardware.
- **systemd:** only version 249 (Ubuntu 22.04) was run. Newer versions handle some sandboxing directives differently;
  `systemd-analyze verify` and a start under the unit are the first things to check there. The unit's
  `SystemCallArchitectures=native` was not exercised (see the warning above).
- **A published release:** no tag has been pushed, so no release archive has been downloaded from GitHub and run
  on a machine other than the local containers.
