# Static-analysis sandbox image

Build explicitly from the repository root:

```bash
docker build --tag ctf-agent-static:local --file sandbox/Dockerfile sandbox
```

This image is for read-only format inspection only (`file`, `unzip -Z`, `readelf`,
`objdump`, and `strings`). Runtime calls must use `--network none`, read-only root
filesystem, dropped capabilities, non-root user, resource limits, and a single read-only
artifact mount. `archive_list` lists ZIP/APK members without extraction. It does not
execute imported challenge binaries, run a shell interactively, or provide a network path.

Use the runner only with a specific artifact inside its challenge workspace:

```bash
python3 -m ctf_agent sandbox-inspect \
  --workspace ctf_challenges/<challenge-id> \
  --artifact ctf_challenges/<challenge-id>/chall.elf \
  --action elf_headers \
  --approve
```
