set dotenv-load := true
set allow-duplicate-recipes

ephemeral := "false"

import? '.devtools-proxy.just'

# Add your project's custom recipes below.
# Standard targets (build, test, lint, ...) come from .devtools-proxy.just.
# Recover that file with: devtools update
