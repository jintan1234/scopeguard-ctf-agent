# Stop and hand off

```text
Stop task <TASK_ID> without further target-facing actions.

Produce a handoff summary containing:

- current workflow phase;
- exact target scope;
- confirmed facts;
- primary and fallback hypotheses;
- commands and artifact paths already attempted;
- failed techniques and why they failed;
- candidate Flags and assurance status;
- the minimum additional information or approval needed to continue.

Do not retry the same action. Do not expand scope.
```
