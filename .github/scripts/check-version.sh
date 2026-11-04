#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 ZCT Studio

set -euo pipefail
if [[ "${GITHUB_EVENT_NAME:-}" != "push" || "${GITHUB_REF:-}" != refs/tags/v* ]]; then
  exit 0
fi
if [[ ! -f VERSION ]]; then
  echo "::error::VERSION 文件不存在" >&2
  exit 1
fi
version=$(cat VERSION)
tag=${GITHUB_REF#refs/tags/v}
if [[ "$tag" != "$version" ]]; then
  echo "::error::发布标签 v${tag} 与 VERSION 中的 ${version} 不一致" >&2
  exit 1
fi
printf '版本检查通过：%s\n' "$version"
