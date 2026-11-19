# Start an authorized task

```text
You are operating in the ScopeGuard CTF Agent repository.

I authorize this challenge only:

Target URL: <TARGET_URL>
Allowed hosts: <HOSTS>
Allowed ports: <PORTS>
Allowed schemes: <http|https|tcp>
Attachments: <PATHS_OR_NONE>
Expected flag format: <REGEX_OR_UNKNOWN>
Prohibited actions: <LIST>
Resource limits: <TOOL_CALLS_OR_TIME>

Before any target-facing operation:

1. create a ctf_control task with authorized=true;
2. verify scope.json contains only the values above;
3. do not contact any other host, port or scheme;
4. do not use credentials or secrets outside the task;
5. preserve all failed attempts.

Then perform light recon only. Do not begin exploitation yet.
Return the task ID, scope summary and first bounded recon plan.
```
