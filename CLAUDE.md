# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview
This repository (`RedTeam-Tools`) is a curated documentation and resource collection of over 150+ tools, scripts, and tips useful for red teaming activities. The project consists entirely of markdown files and a tracking backlog.

## Development Commands
Since this is a documentation-only repository, there are no build steps, compilers, or test suites.

*   **Linting/Formatting**: Ensure `README.md` and `backlog` maintain consistent Markdown formatting.
*   **Link Verification**: Ensure external links and relative links (such as table of contents shortcuts like `[🔙](#tool-list)`) are intact when adding or updating tools.

## Codebase Architecture
*   **README.md**: The primary entry point. Contains a table of contents categorizing tools by attack lifecycle phase (Recon, Execution, Lateral Movement, etc.), followed by sections describing each tool, installation commands, usage examples, and credits.
*   **backlog**: A plain-text list tracking proposed new tools, categorized by phase, containing raw URLs and tool names to be formatted and integrated into `README.md` later.
