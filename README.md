# vibecodepanoply-fixture-public-2

Public test fixture for [vibecodepanoply](https://github.com/Metalline/vibecodepanoply) drills.

This is not a real project. Branches and pull requests here deliberately contain broken or insecure changes
(planted defects, fake workflows, canary values generated at test time) to prove that security gates fail when they should.
Nothing here should be copied into real code.

## How the gate is set up here

`.github/workflows/security-gate.yml` is the owned gate (`pull_request_target`, templates `0.1.0-p0` rendered by `tools/render_gate.py` from the vibecodepanoply branch `v0.1/gate-template`): it runs `.security-gate/bin/gate.py` from the default branch and reads the pull request only as git objects, and it does not run on the pull request that installs it.
There is no ruleset yet: the owner creates it after this branch is merged (`{security-gate, 15368}` on `~DEFAULT_BRANCH`, no bypass), together with the Actions policy that allows `pull_request_target` only for the gate workflow (experiment X16).
A pull request that changes `.github/workflows/` or `.security-gate/` gets SG-TRUST-001 (inconclusive) until the owner runs `bash .security-gate/human/human.sh confirm <pr>` and re-runs the check.
