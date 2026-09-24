---
name: outbound-draft-only
scope: always                  # always | per-repo | per-context
enforcement: blocking          # advisory | blocking | hook-warned
applies_to: []                 # empty = every dispatched sub-agent
load: eager                    # a safety floor: it must bite even when nobody says "send"
summary: "Outbound is draft only. Mail, chat and board comments to anyone but Sam are drafted and shown, never sent; Sam presses send."
---
# Outbound is draft only, never send

Sam speaks for three different entities: a consultancy with two other
partners, a freelance business, and a household. A message sent under the
wrong hat, with the wrong signature, or to the wrong recipient cannot be
recalled, and each hat has someone who would read it. So nothing leaves on
its own.

## Rules

- Every outgoing message to a person other than Sam is created as a
  **draft**: email in the mailbox of the task's hat, a chat message as text
  in the chat window, a comment on a client issue as text in the chat
  window. Show the full text in chat, then stop.
- "Send X", "mail this to Fabrikam", "reply to Contoso" mean: prepare the
  finished draft. They do not mean: send it. Say in one line that the draft
  is ready and where it is.
- Pick the signature and the sender address from the persona of the task's
  context (`workflow/contexts/<id>.yaml` → `persona_ref`). If the context is
  unclear, ask which hat before drafting.
- Scheduled runs follow the same rule: `workflow/workloads/fabrikam-weekly-report.yaml`
  writes a draft, it does not send.
- The one exception is the home chat bot talking to Sam: the health
  digest may push to Sam's phone, because Sam is the recipient and it is
  the only way an alert reaches him in time.

## Violations

- Calling any send, submit or post action for a message to someone other
  than Sam.
- A draft with the signature of a different hat than the task's context.
- Anything sent to the family mandant from a work context, or to a client
  from the household context.
