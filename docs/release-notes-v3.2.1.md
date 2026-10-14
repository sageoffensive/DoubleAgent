# Agent B v3.2.1

Agent B uses one conversation for questions, evidence review and testing directions. A request such as “test finding #3” starts the appropriate bounded Burp task without a mode switch. Questions and evidence reads send no target traffic.

- Finding references match Burp's displayed numbers. Stable identifiers remain internal to tools and evidence links.
- New directions reach the assessment controller, and task outcomes remain available for follow-up questions.
- Concise activity labels explain when Agent B reads evidence or starts work. Detailed activity stays collapsed by default.
- The existing scope, authentication, evidence verification and one-time internet Allow/Deny controls remain in place.

Validation covers synthetic conversation routing, task selection, changed targets, rejected queue creation, finding references, follow-up context, existing security controls, and native bundle smoke checks. No live target assessment was performed as part of this update.
