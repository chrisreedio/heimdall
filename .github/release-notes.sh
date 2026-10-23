#!/bin/sh
# release-notes.sh TAG SHA > notes.md: release notes for a tag. The body of
# the PR that produced the tagged commit, then GitHub's list of every
# change since the previous release, then how to verify the release.
# Needs GH_TOKEN and GITHUB_REPOSITORY. Run before the release is created.
set -eu
tag=${1:?tag}; sha=${2:?sha}; repo=${GITHUB_REPOSITORY:?}
prev=$(gh api "repos/$repo/releases/latest" --jq .tag_name 2>/dev/null || true)
[ "$prev" != "$tag" ] || prev=$(gh api "repos/$repo/releases" --jq '.[1].tag_name // empty' 2>/dev/null || true)

# The PR for the tagged commit, without its attribution footer.
gh api "repos/$repo/commits/$sha/pulls" \
	--jq '[.[] | select(.merged_at)][0] // empty | "## \(.title) (#\(.number))\n\n\(.body // "")"' 2>/dev/null |
	grep -v -e '^🤖 Generated with' -e '^https://claude\.ai/code/' || true
echo

# Everything since the previous release (GitHub's generated notes).
if [ -n "$prev" ]; then
	gh api -X POST "repos/$repo/releases/generate-notes" -f tag_name="$tag" -f target_commitish="$sha" \
		-f previous_tag_name="$prev" --jq .body 2>/dev/null || true
	echo
fi

echo '---'
echo
cat "$(dirname "$0")/../deploy/RELEASE_NOTES.md"
