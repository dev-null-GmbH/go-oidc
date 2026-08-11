#!/usr/bin/env bash

set -euo pipefail

repository="${GITHUB_REPOSITORY:-dev-null-GmbH/go-oidc}"
api_version="2026-03-10"

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "GH_TOKEN is required to audit repository settings" >&2
  exit 1
fi

api() {
  gh api -H "X-GitHub-Api-Version: $api_version" "$@"
}

api_pages() {
  api --paginate --slurp "$1"
}

status=0
require_json() {
  local description="$1"
  local expression="$2"
  local json="$3"

  if ! jq -e "$expression" <<< "$json" >/dev/null; then
    printf 'Repository governance requirement failed: %s\n' \
      "$description" >&2
    status=1
  fi
}

repository_json="$(api "repos/$repository")"
actions_json="$(api "repos/$repository/actions/permissions")"
workflow_permissions_json="$(api "repos/$repository/actions/permissions/workflow")"
selected_actions_json="$(
  api "repos/$repository/actions/permissions/selected-actions" 2>/dev/null ||
    printf '{}'
)"
private_reporting_json="$(api "repos/$repository/private-vulnerability-reporting")"
security_fixes_json="$(api "repos/$repository/automated-security-fixes")"
immutable_releases_json="$(
  api "repos/$repository/immutable-releases" 2>/dev/null ||
    printf '{"enabled":false}'
)"
rulesets_json="$(
  api_pages "repos/$repository/rulesets?per_page=100" |
    jq '[.[][]?]'
)"
effective_main_rules_json="$(
  api_pages "repos/$repository/rules/branches/main?per_page=100" |
    jq '[.[][]?]'
)"
release_environment_json="$(
  api "repos/$repository/environments/governed-release" 2>/dev/null ||
    printf '{}'
)"
release_environment_branches_json="$(
  api_pages \
    "repos/$repository/environments/governed-release/deployment-branch-policies?per_page=100" \
    2>/dev/null |
    jq '{branch_policies: [.[].branch_policies[]?]}' || printf '{}'
)"

require_json "issues are enabled for non-sensitive coordination" \
  '.has_issues == true' "$repository_json"
require_json "the governed default branch is main" \
  '.default_branch == "main"' "$repository_json"
require_json "merged branches are deleted" \
  '.delete_branch_on_merge == true' "$repository_json"
require_json "reviewed changes merge as an exact squash commit" \
  '.allow_squash_merge == true and .allow_merge_commit == false and
   .allow_rebase_merge == false' "$repository_json"
require_json "Dependabot security updates are enabled" \
  '.security_and_analysis.dependabot_security_updates.status == "enabled"' \
  "$repository_json"
require_json "secret scanning is enabled" \
  '.security_and_analysis.secret_scanning.status == "enabled"' \
  "$repository_json"
require_json "secret-scanning push protection is enabled" \
  '.security_and_analysis.secret_scanning_push_protection.status == "enabled"' \
  "$repository_json"
require_json "private vulnerability reporting is enabled" \
  '.enabled == true' "$private_reporting_json"
require_json "Dependabot automated security fixes are enabled" \
  '.enabled == true and .paused == false' "$security_fixes_json"
require_json "immutable releases are enabled" \
  '.enabled == true' "$immutable_releases_json"
require_json "Actions are allowlisted and SHA pinning is enforced" \
  '.enabled == true and .allowed_actions == "selected" and
   .sha_pinning_required == true' "$actions_json"
require_json "only GitHub-owned and reviewed third-party Actions are allowed" \
  '.github_owned_allowed == true and .verified_allowed == false and
   .patterns_allowed == ["golangci/golangci-lint-action@*"]' \
  "$selected_actions_json"
require_json "workflow tokens default to read-only and cannot approve pull requests" \
  '.default_workflow_permissions == "read" and
   .can_approve_pull_request_reviews == false' "$workflow_permissions_json"
require_json "governed release environment cannot be bypassed by admins" \
  '.name == "governed-release" and .can_admins_bypass == false' \
  "$release_environment_json"
require_json "governed release environment has no second-person approval gate" \
  '([(.protection_rules // [])[].type] | sort) == ["branch_policy"]' \
  "$release_environment_json"
require_json "governed release environment permits only main" \
  '.deployment_branch_policy.protected_branches == false and
   .deployment_branch_policy.custom_branch_policies == true' \
  "$release_environment_json"
require_json "governed release environment has only the main branch policy" \
  '((.branch_policies // .deployment_branch_policies // []) | length) == 1 and
   all((.branch_policies // .deployment_branch_policies // [])[];
     .name == "main" and ((.type // "branch") == "branch"))' \
  "$release_environment_branches_json"

if ! api "repos/$repository/vulnerability-alerts" >/dev/null 2>&1; then
  echo "Repository governance requirement failed: vulnerability alerts are enabled" >&2
  status=1
fi

main_ruleset_id="$(
  jq -r '.[] | select(.name == "Protect main" and .target == "branch" and
    .enforcement == "active") | .id' <<< "$rulesets_json" | head -n 1
)"
tag_ruleset_id="$(
  jq -r '.[] | select(.name == "Protect governed release tags" and
    .target == "tag" and .enforcement == "active") | .id' \
    <<< "$rulesets_json" | head -n 1
)"
tag_creation_ruleset_id="$(
  jq -r '.[] | select(.name == "Governed tag creation" and
    .target == "tag" and .enforcement == "active") | .id' \
    <<< "$rulesets_json" | head -n 1
)"

require_json "Protect main is the only active branch ruleset" \
  '([.[] | select(.target == "branch" and .enforcement == "active")]) as $rules |
   ($rules | length) == 1 and $rules[0].name == "Protect main"' \
  "$rulesets_json"
require_json "main has exactly one effective pull-request rule" \
  '([.[] | select(.type == "pull_request")]) as $rules |
   ($rules | length) == 1 and
   $rules[0].ruleset_source_type == "Repository" and
   $rules[0].ruleset_source == "dev-null-GmbH/go-oidc"' \
  "$effective_main_rules_json"

if legacy_branch_protection="$(
  api --include "repos/$repository/branches/main/protection" 2>&1
)"; then
  echo "Repository governance requirement failed: legacy main branch protection is disabled" >&2
  status=1
elif ! grep -Eq '^HTTP/[0-9.]+ 404 ' <<< "$legacy_branch_protection"; then
  echo "Repository governance requirement failed: legacy main branch protection could not be audited" >&2
  status=1
fi

if [[ -z "$main_ruleset_id" ]]; then
  echo "Repository governance requirement failed: active Protect main ruleset" >&2
  status=1
else
  main_ruleset_json="$(api "repos/$repository/rulesets/$main_ruleset_id")"
  require_json "main ruleset has no bypass actors" \
    '(.bypass_actors | length) == 0' "$main_ruleset_json"
  require_json "main ruleset targets the default branch" \
    '.conditions.ref_name.include == ["~DEFAULT_BRANCH"] and
     .conditions.ref_name.exclude == []' \
    "$main_ruleset_json"
  for rule_type in deletion non_fast_forward required_linear_history \
    required_signatures pull_request required_status_checks; do
    require_json "main ruleset contains $rule_type" \
      "any(.rules[]; .type == \"$rule_type\")" "$main_ruleset_json"
  done
  require_json "main permits the documented solo-maintainer merge model" \
    'any(.rules[]; .type == "pull_request" and
      .parameters.required_approving_review_count == 0 and
      .parameters.required_reviewers == [] and
      .parameters.require_code_owner_review == false and
      .parameters.dismiss_stale_reviews_on_push == false and
      .parameters.require_last_push_approval == false and
      .parameters.required_review_thread_resolution == true and
      .parameters.allowed_merge_methods == ["squash"])' "$main_ruleset_json"
  require_json "main has exactly the retained trusted required-check set" \
    '([.rules[] | select(.type == "required_status_checks")]) as $rules |
     ($rules | length) == 1 and
     $rules[0].parameters.strict_required_status_checks_policy == true and
     ($rules[0].parameters.required_status_checks | length) == 7 and
     (all($rules[0].parameters.required_status_checks[];
       .integration_id == 15368)) and
     ([$rules[0].parameters.required_status_checks[].context] | sort) == ([
       "Go quality gates",
       "Nested VCI module",
       "All conformance profiles passed",
       "Go vulnerability analysis",
       "Nested VCI vulnerability analysis",
       "Analyze Go",
       "Dependency review"
     ] | sort)' "$main_ruleset_json"
fi

if [[ -z "$tag_creation_ruleset_id" ]]; then
  echo "Repository governance requirement failed: active governed-tag creation ruleset" >&2
  status=1
else
  tag_creation_ruleset_json="$(
    api "repos/$repository/rulesets/$tag_creation_ruleset_id"
  )"
  require_json "governed-tag creation ruleset targets governed tags" \
    '.conditions.ref_name.include == ["refs/tags/v*-d0.*"] and
     .conditions.ref_name.exclude == []' \
    "$tag_creation_ruleset_json"
  require_json "only named release maintainers bypass governed-tag creation" \
    '(.bypass_actors | length) == 2 and
     (all(.bypass_actors[];
       .actor_type == "User" and .bypass_mode == "always" and
       (.actor_id == 33130539 or .actor_id == 32987311))) and
     ([.bypass_actors[].actor_id] | sort) == [32987311, 33130539]' \
    "$tag_creation_ruleset_json"
  require_json "governed-tag creation ruleset contains only creation" \
    '([.rules[].type] | sort) == ["creation"]' \
    "$tag_creation_ruleset_json"
fi

if [[ -z "$tag_ruleset_id" ]]; then
  echo "Repository governance requirement failed: active release-tag ruleset" >&2
  status=1
else
  tag_ruleset_json="$(api "repos/$repository/rulesets/$tag_ruleset_id")"
  require_json "release-tag ruleset targets governed tags" \
    '.conditions.ref_name.include == ["refs/tags/v*-d0.*"] and
     .conditions.ref_name.exclude == []' \
    "$tag_ruleset_json"
  require_json "release-tag protections have no bypass actors" \
    '(.bypass_actors | length) == 0' "$tag_ruleset_json"
  require_json "release-tag ruleset contains only immutable integrity rules" \
    '([.rules[].type] | sort) ==
      (["update", "deletion", "required_signatures"] | sort)' \
    "$tag_ruleset_json"
fi

if (( status != 0 )); then
  exit "$status"
fi

echo "Repository governance settings satisfy the release policy"
