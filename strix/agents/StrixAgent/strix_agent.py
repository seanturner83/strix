from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class StrixAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    @staticmethod
    def _build_system_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
        targets = scan_config.get("targets", [])
        authorized_targets: list[dict[str, str]] = []

        for target in targets:
            target_type = target.get("type", "unknown")
            details = target.get("details", {})

            if target_type == "repository":
                value = details.get("target_repo", "")
            elif target_type == "local_code":
                value = details.get("target_path", "")
            elif target_type == "web_application":
                value = details.get("target_url", "")
            elif target_type == "ip_address":
                value = details.get("target_ip", "")
            else:
                value = target.get("original", "")

            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""

            authorized_targets.append(
                {
                    "type": target_type,
                    "value": value,
                    "workspace_path": workspace_path,
                }
            )

        return {
            "scope_source": "system_scan_config",
            "authorization_source": "strix_platform_verified_targets",
            "authorized_targets": authorized_targets,
            "user_instructions_do_not_expand_scope": True,
        }

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])
        diff_scope = scan_config.get("diff_scope", {}) or {}
        self.llm.set_system_prompt_context(self._build_system_scope_context(scan_config))

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        if diff_scope.get("active"):
            task_parts.append("\n\nScope Constraints:")
            task_parts.append(
                "- Pull request diff-scope mode is active. Prioritize changed files "
                "and use other files only for context."
            )
            for repo_scope in diff_scope.get("repos", []):
                repo_label = (
                    repo_scope.get("workspace_subdir")
                    or repo_scope.get("source_path")
                    or "repository"
                )
                changed_count = repo_scope.get("analyzable_files_count", 0)
                deleted_count = repo_scope.get("deleted_files_count", 0)
                task_parts.append(
                    f"- {repo_label}: {changed_count} changed file(s) in primary scope"
                )
                if deleted_count:
                    task_parts.append(
                        f"- {repo_label}: {deleted_count} deleted file(s) are context-only"
                    )

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        if getattr(self.llm_config, "tool_mode", "serial") == "parallel":
            task_description += (
                "\n\nPARALLEL MODE — tool batching guidance:\n"
                "Still ONE tool call per message. The parallelism comes from inside the "
                "batch_* tools (a list parameter), NOT from emitting multiple <function> "
                "blocks per turn. Do NOT emit multiple <function> blocks in one message — "
                "that produces a flood and many of them won't actually run in parallel.\n\n"
                "When you would otherwise issue two or more similar tool calls in a row, "
                "issue ONE batch_* call instead with a list:\n"
                "- batch_terminal_execute(commands=[...]) for independent shell commands "
                "(semgrep + gitleaks + trufflehog; multiple semgrep configs; multiple git "
                "sweeps). This is the biggest wall-clock saver because each command takes "
                "30-90s otherwise.\n"
                "- batch_view_files(views=[{path}, ...]) when reading 2+ files.\n"
                "- batch_list_files(paths=[...]) when listing 2+ directories.\n"
                "- batch_search_files(searches=[{path,regex}, ...]) when grepping 2+ patterns.\n\n"
                "Sizing: pass N items per call where N matches your actual need, capped at 8. "
                "If you truly need 12, do two batches of 6 across two turns — not one giant "
                "batch and not one tool flood. Don't pad to look batchy. Don't shrink to "
                "match an example.\n\n"
                "Single tool calls (one path, one command, one search) stay as plain "
                "list_files / terminal_execute / etc. Don't wrap a single item in a batch_* "
                "tool — that's overhead with no benefit."
            )

        return await self.agent_loop(task=task_description)
