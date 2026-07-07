index=github url IN ("*.enterprise.githubcopilot.com*", "*api.github.com/copilot_internal*", "*api.github.com/user*", "*github.com/login*", "*copilot-proxy.githubusercontent.com*", "*origin-tracker.githubusercontent.com*", "*copilot-telemetry.githubusercontent.com*", "*default.exp-tas.com*")
| stats count by user, action
