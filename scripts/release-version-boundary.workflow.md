# Wiring the release workflow (#7541)

This folder's helper rejects tag/Cargo prefix collisions. Point the
`check-version` job at it by replacing the `Verify crate version matches tag`
run step in `.github/workflows/release.yml` with:

```yaml
      - name: Verify crate version matches tag
        # Accept the exact Cargo version or a hyphen-delimited prerelease suffix
        # (e.g. 1.4.8 and 1.4.8-rc.1). Reject prefix collisions such as 1.4.80
        # or 1.4.8junk that the previous `"$cargo_ver"*` glob allowed.
        env:
          TAG: ${{ needs.get-version.outputs.version }}
        run: |
          cargo_ver=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "tempo").version')
          bash scripts/check-release-tag-version.sh "$TAG" "$cargo_ver"
```

A maintainer with `workflow` scope can apply this on the branch; the OAuth
token used for this contribution cannot push `.github/workflows/*` changes.
